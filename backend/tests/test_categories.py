"""Product to technology-category mapping, its review queue and the hand-made assignments."""

import httpx
import pytest
from fastapi.testclient import TestClient

from app import queries, runner, state
from app.main import app
from app.sources import SOURCES
from app.taxonomy import mapping

from .test_nvd import payload, record


def nvd_entry(cve_id: str, products: list[str], published: str = "2026-01-10T00:00:00.000", kev=None):
    entry = record(cve_id, published=published, cisaExploitAdd=kev)
    entry["cve"]["configurations"] = [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": f"cpe:2.3:a:{p.replace(':', ':')}:1.0:*:*:*:*:*:*:*"} for p in products
    ]}]}]
    return entry


@pytest.fixture
def catalogue(settings, monkeypatch):
    """A small NVD catalogue with products that the rules should and should not catch."""
    monkeypatch.setenv("FUC_NVD_DELAY_SECONDS", "0")
    from app.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    entries = [
        nvd_entry("CVE-2026-0001", ["fortinet:fortios"], kev="2026-02-01"),
        nvd_entry("CVE-2026-0002", ["fortinet:fortios", "fortinet:fortiproxy"]),
        nvd_entry("CVE-2026-0003", ["wordpress:wordpress"]),
        nvd_entry("CVE-2026-0004", ["acme:gizmotron"]),  # nothing should match this
        nvd_entry("CVE-2026-0005", ["acme:gizmotron", "microsoft:windows_10"]),
        nvd_entry("CVE-2015-0006", ["acme:gizmotron"], published="2015-01-01T00:00:00.000"),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payload(entries, len(entries)))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    runner.run_source(settings, "nvd", client=client)
    return settings


def test_rules_catch_the_obvious_and_leave_the_rest_alone():
    assert mapping.classify("fortinet:fortios")[:2] == ("firewall_security_appliance", "rule")
    assert mapping.classify("paloaltonetworks:pan-os")[0] == "firewall_security_appliance"
    assert mapping.classify("cisco:ios_xe")[0] == "router_network_edge"
    assert mapping.classify("apple:iphone_os")[0] == "mobile_device"
    assert mapping.classify("microsoft:exchange_server")[0] == "mail_collaboration"
    assert mapping.classify("wordpress:wordpress")[0] == "web_cms"
    assert mapping.classify("vmware:esxi")[0] == "virtualization_cloud"
    assert mapping.classify("siemens:simatic_s7")[0] == "iot_ot_building"
    assert mapping.classify("microsoft:windows_10")[0] == "operating_system"
    assert mapping.classify("acme:gizmotron") == ("unmapped", "unmapped", "")


def test_rules_only_use_categories_that_exist():
    rules = mapping.load_rules()
    known = set(mapping.category_ids())
    assert {category for _, category, _ in rules["rules"]} <= known
    assert "unmapped" not in known  # it is a state, not a category


def test_the_table_is_built_from_the_catalogue(catalogue):
    settings = catalogue
    # Collecting the catalogue builds the table: no separate step to forget.
    assert mapping.is_current(settings) and runner.refresh_categories(settings) is None
    assert queries.category_products(settings)["total"] == 5  # five distinct products

    rows = {r["product"]: r for r in queries.category_products(settings)["items"]}
    assert rows["fortinet:fortios"]["category"] == "firewall_security_appliance"
    assert rows["fortinet:fortios"]["cve_count"] == 2 and rows["fortinet:fortios"]["kev_count"] == 1
    assert rows["acme:gizmotron"]["category"] == "unmapped"
    assert rows["acme:gizmotron"]["cve_count"] == 3 and rows["acme:gizmotron"]["recent_cve_count"] == 2

    # the queue puts what matters first: exploited, then recent, then merely numerous
    queue = queries.category_products(settings, assigned_by="unmapped")["items"]
    assert [r["product"] for r in queue] == ["acme:gizmotron"]


def test_coverage_counts_cves_not_just_products(catalogue):
    settings = catalogue
    runner.refresh_categories(settings)
    coverage = queries.categories_coverage(settings)
    assert coverage["products"] == 5 and coverage["products_mapped"] == 4
    assert coverage["cves"] == 6 and coverage["cves_mapped"] == 4  # CVE-2026-0005 counts: it has Windows
    assert coverage["kev_cves"] == 1 and coverage["kev_cves_mapped"] == 1

    summary = {r["category"]: r for r in queries.categories_summary(settings)["items"]}
    assert summary["firewall_security_appliance"]["cves"] == 2
    assert summary["firewall_security_appliance"]["kev_cves"] == 1
    assert summary["firewall_security_appliance"]["kev_share"] == 0.5
    assert set(summary) == {"firewall_security_appliance", "web_cms", "operating_system"}


def test_a_hand_made_assignment_wins_and_can_be_taken_back(catalogue):
    settings = catalogue
    with TestClient(app) as api:
        api.post("/api/v1/categories/rebuild")
        assert api.put("/api/v1/categories/products/acme:gizmotron",
                       json={"category": "nonsense"}).status_code == 422

        ok = api.put("/api/v1/categories/products/acme:gizmotron",
                     json={"category": "iot_ot_building", "note": "industrial controller"})
        assert ok.status_code == 200
        row = api.get("/api/v1/categories/products", params={"search": "gizmo"}).json()["items"][0]
        assert (row["category"], row["assigned_by"]) == ("iot_ot_building", "manual")
        assert api.get("/api/v1/categories/coverage").json()["products_manual"] == 1
        assert api.get("/api/v1/categories/coverage").json()["cves_mapped"] == 6

        # a rule change must not quietly overwrite a decision someone made
        assert state.product_categories(settings.state_db) == {"acme:gizmotron": "iot_ot_building"}
        runner.refresh_categories(settings, force=True)
        assert api.get("/api/v1/categories/products", params={"search": "gizmo"}).json()["items"][0][
            "assigned_by"] == "manual"

        assert api.delete("/api/v1/categories/products/acme:gizmotron").json()["removed"] is True
        assert api.get("/api/v1/categories/products", params={"search": "gizmo"}).json()["items"][0][
            "category"] == "unmapped"
        assert api.delete("/api/v1/categories/products/acme:gizmotron").json()["removed"] is False


def test_the_table_goes_stale_when_a_decision_is_made(catalogue):
    settings = catalogue
    runner.refresh_categories(settings)
    assert mapping.is_current(settings) is True
    state.set_product_category(settings.state_db, "acme:gizmotron", "iot_ot_building")
    assert mapping.is_current(settings) is False
    runner.refresh_categories(settings)
    assert mapping.is_current(settings) is True


def test_a_cve_profile_carries_its_categories(catalogue):
    settings = catalogue
    runner.refresh_categories(settings)
    with TestClient(app) as api:
        profile = api.get("/api/v1/cve/CVE-2026-0005").json()
        assert profile["categories"] == ["operating_system"]  # gizmotron is unmapped
        assert api.get("/api/v1/cve/CVE-2026-0002").json()["categories"] == ["firewall_security_appliance"]


@pytest.mark.parametrize(
    "product, category",
    [
        # gaps the review queue showed on the real catalogue
        ("microsoft:internet_explorer", "browser_client"),
        ("microsoft:open_xml_file_format_converter", "browser_client"),
        ("adobe:air", "browser_client"),
        ("apple:quicktime", "browser_client"),
        ("oracle:solaris", "operating_system"),
        ("sun:jdk", "operating_system"),
        ("cpanel:cpanel", "remote_management"),
        ("hp:openview_network_node_manager", "remote_management"),
        ("al-enterprise:omnipcx_enterprise_communication_server", "router_network_edge"),
        ("phpbb:phpbb", "web_cms"),
        # second pass, against the full catalogue
        ("apple:visionos", "mobile_device"),
        ("arm:valhall_gpu_kernel_driver", "mobile_device"),
        ("citrix:netscaler_application_delivery_controller", "firewall_security_appliance"),
        ("microsoft:365_apps", "browser_client"),
        ("webkitgtk:webkitgtk", "browser_client"),
        (r"webkitgtk:webkitgtk\+", "browser_client"),
        ("trendmicro:officescan", "firewall_security_appliance"),
        ("cisco:rv340_firmware", "router_network_edge"),
        ("oracle:agile_product_lifecycle_management", "enterprise_application"),
        ("langflow:langflow", "enterprise_application"),
        # an escaping mistake made this one match a literal backslash, never a dot
        ("microsoft:.net_framework", "operating_system"),
        # third pass
        ("redhat:satellite", "remote_management"),
        ("redhat:software_collections", "operating_system"),
        ("redhat:gluster_storage_server_for_on-premise", "database_storage"),
        ("papercut:papercut_ng", "remote_management"),
        ("citrix:application_delivery_controller_firmware", "firewall_security_appliance"),
        ("microsoft:server_message_block", "operating_system"),
        ("fortinet:fortiswitchmanager", "firewall_security_appliance"),
        ("oracle:http_server", "web_cms"),
        ("kentico:xperience", "web_cms"),
    ],
)
def test_rules_cover_what_the_queue_turned_up(product, category):
    assert mapping.classify(product)[0] == category


@pytest.mark.parametrize(
    "product, category",
    [
        ("fortinet:fortios", "firewall_security_appliance"),
        ("cisco:ios_xe", "router_network_edge"),
        ("wordpress:wordpress", "web_cms"),
        ("vmware:esxi", "virtualization_cloud"),
        ("oracle:database", "database_storage"),
        ("microsoft:exchange_server", "mail_collaboration"),
        ("apple:iphone_os", "mobile_device"),
        ("microsoft:windows_10", "operating_system"),
        ("siemens:simatic_s7", "iot_ot_building"),
        ("ivanti:connect_secure", "vpn_remote_access"),
        ("redhat:enterprise_linux", "operating_system"),
        ("oracle:weblogic_server", "enterprise_application"),
    ],
)
def test_widening_the_rules_does_not_move_what_already_worked(product, category):
    """Rules are first-match-wins, so a new pattern can quietly steal an older one."""
    assert mapping.classify(product)[0] == category


def test_coverage_works_when_the_catalogue_spans_several_files(catalogue, monkeypatch):
    """The real catalogue is dozens of part files; with one file a wrong parameter list
    still happened to work, which is how this stayed hidden."""
    settings = catalogue
    source = SOURCES["nvd"]
    day = source.snapshot_dates(settings)[0]
    folder = source.curated_path(settings, day).parent
    original = next(folder.glob("*.parquet"))
    for index in range(3):
        (folder / f"part-copy-{index}.parquet").write_bytes(original.read_bytes())
    assert len(source.curated_files(settings)) == 4

    runner.refresh_categories(settings, force=True)
    coverage = queries.categories_coverage(settings)
    assert coverage["cves"] == 6 and coverage["cves_mapped"] == 4  # same answer, more files
    assert coverage["products"] == 5
