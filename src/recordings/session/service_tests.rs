//! Inter-profile CAS boundary cases and full service session flows.
//!
//! Each relying party admits only its reviewed origins, a password form may
//! target only the selected service declaration, and a library CAS value may
//! leave the URL only on the library origin, while an iHome fragment token
//! binds only on the reviewed platform web prefix. The flows below drive one
//! real in-memory CAS login plus exactly one business read against a loopback
//! stand-in whose certificate authority is pinned to the test client alone.
//! Every input here is synthetic; no campus network, credential store or campus
//! source is touched.
#![cfg(test)]

use super::*;
use std::collections::BTreeMap;

const SSO_LOGIN: &str = "https://sso.buaa.edu.cn/login";
const BOOKING_ORIGIN: &str = "https://booking.lib.buaa.edu.cn";
/// Synthetic sign-on material shared by every flow in this file.
const SESSION_USERNAME: &str = "synthetic-student";
const SESSION_PASSWORD: &str = "synthetic-pass";
/// The terminal CAS value the library relying party hands over.
const SMART_CAS_VALUE: &str = "ST-terminal-synthetic";
/// The bearer token the library exchange issues.
const LIBRARY_TOKEN: &str = "synthetic-library-token-7h3k";
/// Scoped application cookies; neither is a sign-on credential.
const SMART_APP_COOKIE: &str = "smart_session=synthetic-app-session";
const LIBRARY_APP_COOKIE: &str = "lib_session=synthetic-library-session";
const ALL_SERVICES: [CasService; 4] = [
    CasService::Classroom,
    CasService::SmartClassrooms,
    CasService::Library,
    CasService::Ihome,
];

fn url(input: &str) -> Url {
    Url::parse(input).expect("synthetic url")
}

fn pinned(service: CasService) -> Url {
    pinned_login_url(service).expect("pinned login url")
}

/// The decoded `service=` value the pinned login page carries for a profile.
fn pinned_service_value(service: CasService) -> String {
    pinned(service)
        .query_pairs()
        .find(|(name, _)| name.as_ref() == "service")
        .map(|(_, value)| value.into_owned())
        .expect("pinned login carries a service pair")
}

fn login_with_query(pairs: &[(&str, &str)]) -> Url {
    let mut url = url(SSO_LOGIN);
    {
        let mut query = url.query_pairs_mut();
        for &(name, value) in pairs {
            query.append_pair(name, value);
        }
    }
    url
}

fn credential(service: CasService, input: &str) -> Result<Option<Zeroizing<String>>, Error> {
    terminal_service_credential(service, &url(input))
}

#[test]
fn each_profile_admits_only_its_reviewed_origins() {
    for service in ALL_SERVICES {
        assert!(allowed(&url(SSO_LOGIN), service));
        assert!(allowed(&url("https://sso.buaa.edu.cn"), service));
    }
    // The classroom callback and platform stay confined to the Classroom
    // profile; neither smart relying party may reach them.
    for host in ["yjapi.msa.buaa.edu.cn", "classroom.msa.buaa.edu.cn"] {
        let candidate = url(&format!("https://{host}/"));
        assert!(allowed(&candidate, CasService::Classroom), "{host}");
        assert!(!allowed(&candidate, CasService::SmartClassrooms), "{host}");
        assert!(!allowed(&candidate, CasService::Library), "{host}");
        assert!(!allowed(&candidate, CasService::Ihome), "{host}");
    }
    let app = url("https://app.buaa.edu.cn/a_buaa/api/cas/index");
    assert!(allowed(&app, CasService::SmartClassrooms));
    assert!(!allowed(&app, CasService::Classroom));
    assert!(!allowed(&app, CasService::Library));
    assert!(!allowed(&app, CasService::Ihome));
    let booking = url("https://booking.lib.buaa.edu.cn/v4/login/cas");
    assert!(allowed(&booking, CasService::Library));
    assert!(!allowed(&booking, CasService::Classroom));
    assert!(!allowed(&booking, CasService::SmartClassrooms));
    assert!(!allowed(&booking, CasService::Ihome));
    // The iHome profile admits the sign-on host and the platform host only;
    // the plaintext callback is normalized to HTTPS before admission, so the
    // raw http spelling is not an admissible request target.
    let ihome_callback = url("https://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic");
    assert!(allowed(&ihome_callback, CasService::Ihome));
    assert!(!allowed(&ihome_callback, CasService::Classroom));
    assert!(!allowed(&ihome_callback, CasService::SmartClassrooms));
    assert!(!allowed(&ihome_callback, CasService::Library));
    assert!(!allowed(
        &url("http://i.buaa.edu.cn/api/authLogin"),
        CasService::Ihome
    ));
    // Origin admission is host-scoped: arbitrary paths and queries on a
    // reviewed host remain admitted, so a foreign path cannot harden a host.
    assert!(allowed(
        &url("https://app.buaa.edu.cn/site/classRoomQuery/index?x=1"),
        CasService::SmartClassrooms
    ));
    assert!(allowed(
        &url("https://classroom.msa.buaa.edu.cn/arbitrary/path?q=v"),
        CasService::Classroom
    ));
}

#[test]
fn allowed_refuses_shaped_origins_and_lookalike_hosts() {
    for service in ALL_SERVICES {
        for candidate in [
            "http://sso.buaa.edu.cn/login", // plaintext scheme
            "https://operator@sso.buaa.edu.cn/login",
            "https://operator:secret@sso.buaa.edu.cn/login",
            "https://sso.buaa.edu.cn:4443/login", // nondefault port
            "https://sso.buaa.edu.cn/login#fragment",
            "https://sso.buaa.edu.cn./login", // trailing-dot host
            "https://sso.buaa.edu.cn.attacker.example/login", // suffix lookalike
            "http://app.buaa.edu.cn/",
            "http://booking.lib.buaa.edu.cn/",
            "https://app.buaa.edu.cn.attacker.example/",
            "https://booking.lib.buaa.edu.cn.attacker.example/",
            "https://evil.booking.lib.buaa.edu.cn/",
            "https://lib.buaa.edu.cn/",
            "https://ihome.buaa.edu.cn/",
            "https://gw.buaa.edu.cn/",
            "http://i.buaa.edu.cn/api/authLogin",
            "http://i.buaa.edu.cn/web/",
            "https://operator@i.buaa.edu.cn/api/authLogin",
            "https://i.buaa.edu.cn:4443/api/authLogin",
            "https://i.buaa.edu.cn./api/authLogin",
            "https://i.buaa.edu.cn.attacker.example/api/authLogin",
            "https://sub.i.buaa.edu.cn/api/authLogin",
        ] {
            assert!(!allowed(&url(candidate), service), "{candidate}");
        }
    }
}

#[test]
fn pinned_login_route_accepts_only_the_selected_service() {
    for service in ALL_SERVICES {
        // No query and the exact selected declaration are valid form targets.
        assert!(pinned_login_route(&url(SSO_LOGIN), service));
        let selected = pinned_service_value(service);
        assert!(pinned_login_route(
            &login_with_query(&[("service", selected.as_str())]),
            service
        ));
        // A form carrying another relying party's declaration never matches:
        // the classroom pin is not a smart or library target and vice versa.
        for other in ALL_SERVICES {
            if other == service {
                continue;
            }
            assert!(!pinned_login_route(&pinned(other), service));
            let foreign = pinned_service_value(other);
            assert!(!pinned_login_route(
                &login_with_query(&[("service", foreign.as_str())]),
                service
            ));
        }
    }
}

#[test]
fn smart_route_declares_no_auto_redirect_and_no_other_extra_pair() {
    let selected = pinned_service_value(CasService::SmartClassrooms);
    // The source-declared flag is accepted next to the service pair.
    assert!(pinned_login_route(
        &login_with_query(&[("service", &selected), ("noAutoRedirect", "1")]),
        CasService::SmartClassrooms
    ));
    // The flag alone is not a credential route, and only the literal reviewed
    // value binds; tampered or duplicated flags refuse.
    assert!(!pinned_login_route(
        &login_with_query(&[("noAutoRedirect", "1")]),
        CasService::SmartClassrooms
    ));
    for tampered in ["0", "2", "true"] {
        assert!(!pinned_login_route(
            &login_with_query(&[("service", &selected), ("noAutoRedirect", tampered)]),
            CasService::SmartClassrooms
        ));
    }
    assert!(!pinned_login_route(
        &login_with_query(&[
            ("service", &selected),
            ("noAutoRedirect", "1"),
            ("noAutoRedirect", "1"),
        ]),
        CasService::SmartClassrooms
    ));
    // Other profiles never accept the smart-only flag on their forms.
    for service in [
        CasService::Classroom,
        CasService::Library,
        CasService::Ihome,
    ] {
        let value = pinned_service_value(service);
        assert!(!pinned_login_route(
            &login_with_query(&[("service", &value), ("noAutoRedirect", "1")]),
            service
        ));
    }
}

#[test]
fn pinned_login_route_refuses_query_widening() {
    for service in ALL_SERVICES {
        let selected = pinned_service_value(service);
        let selected = selected.as_str();
        for pairs in [
            vec![("service", selected), ("service", selected)],
            vec![
                ("service", selected),
                ("service", "https://attacker.example/cas"),
            ],
            vec![("service", selected), ("from", "operator")],
            vec![("from", "operator"), ("service", selected)],
            vec![("ticket", "ST-synthetic"), ("service", selected)],
            vec![("service", "")],
            vec![("service", "https://attacker.example/cas")],
            vec![("service", "https://sso.buaa.edu.cn/login")],
            vec![("SERVICE", selected)],
            vec![("service", "https://app.buaa.edu.cn/a_buaa/api/cas/index")],
        ] {
            let target = login_with_query(&pairs);
            assert!(!pinned_login_route(&target, service), "{}", target.as_str());
        }
    }
}

#[test]
fn pinned_login_route_refuses_exfiltration_shaping() {
    for service in ALL_SERVICES {
        for action in [
            "http://sso.buaa.edu.cn/login",
            "https://operator@sso.buaa.edu.cn/login",
            "https://operator:secret@sso.buaa.edu.cn/login",
            "https://sso.buaa.edu.cn:4443/login",
            "https://sso.buaa.edu.cn/login#fragment",
            "https://sso.buaa.edu.cn/login/extra",
            "https://sso.buaa.edu.cn/login/",
            "https://sso.buaa.edu.cn/",
            "https://sso.buaa.edu.cn./login",
            "https://sso.buaa.edu.cn.attacker.example/login",
            "https://yjapi.msa.buaa.edu.cn/login",
            "https://app.buaa.edu.cn/login",
            "https://booking.lib.buaa.edu.cn/login",
        ] {
            assert!(!pinned_login_route(&url(action), service), "{action}");
        }
    }
}

#[test]
fn library_terminal_credential_is_extracted_only_on_booking_origin() {
    let extracted = credential(
        CasService::Library,
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=ST-library-synthetic",
    )
    .expect("valid cas query")
    .expect("credential present");
    assert_eq!(extracted.as_str(), "ST-library-synthetic");

    // The upstream selector binds `cas` from the fragment as well as the
    // query. Extraction happens in memory on the terminal redirect URL; it is
    // never fetched, so a terminal fragment is admissible here even though
    // allowed() refuses fragments on request URLs.
    for (input, expected) in [
        (
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-fragment",
            "ST-fragment",
        ),
        (
            "https://booking.lib.buaa.edu.cn/#/route?cas=ST-routed-fragment",
            "ST-routed-fragment",
        ),
        (
            "https://booking.lib.buaa.edu.cn/#%63as=ST-encoded-name",
            "ST-encoded-name",
        ),
        (
            "https://booking.lib.buaa.edu.cn/?cas=ST-query#route/segment",
            "ST-query",
        ),
        (
            "https://booking.lib.buaa.edu.cn/?cas=%46%46%46#/route",
            "FFF",
        ),
    ] {
        let value = credential(CasService::Library, input)
            .expect("admissible fragment credential")
            .expect("credential present");
        assert_eq!(value.as_str(), expected, "{input}");
    }

    // A fragment is admitted for extraction but supplies no credential by
    // itself; neither does a bare hash route.
    for input in [
        "https://booking.lib.buaa.edu.cn/#/route",
        "https://booking.lib.buaa.edu.cn/#from=wap",
        "https://booking.lib.buaa.edu.cn/?from=wap#/seat-map",
    ] {
        assert!(
            credential(CasService::Library, input)
                .expect("admissible url")
                .is_none(),
            "{input}"
        );
    }

    // No `cas` pair means no credential: other names, a name-case variant and
    // a prefix lookalike never stand in for it.
    for input in [
        "https://booking.lib.buaa.edu.cn/v4/login/cas",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?ticket=ST-synthetic",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?from=wap",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?CAS=ST-synthetic",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?xcas=ST-synthetic",
        "https://booking.lib.buaa.edu.cn/",
        "https://sso.buaa.edu.cn/login",
    ] {
        assert!(
            credential(CasService::Library, input)
                .expect("admissible url")
                .is_none(),
            "{input}"
        );
    }

    // Non-cas parameters may travel with the credential without widening it.
    let with_extra = credential(
        CasService::Library,
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=abc&from=wap&ticket=ST-synthetic",
    )
    .expect("extra params")
    .expect("credential");
    assert_eq!(with_extra.as_str(), "abc");

    // Percent-decoding applies to the name and value before binding.
    let decoded = credential(
        CasService::Library,
        "https://booking.lib.buaa.edu.cn/?%63as=a%20b",
    )
    .expect("encoded pair")
    .expect("credential");
    assert_eq!(decoded.as_str(), "a b");

    // The bound is inclusive; one byte past it refuses.
    let bounded = url(&format!(
        "{BOOKING_ORIGIN}/v4/login/cas?cas={}",
        "a".repeat(4096)
    ));
    let bounded = terminal_service_credential(CasService::Library, &bounded)
        .expect("bounded value")
        .expect("credential");
    assert_eq!(bounded.as_str().len(), 4096);
    let over = url(&format!(
        "{BOOKING_ORIGIN}/v4/login/cas?cas={}",
        "a".repeat(4097)
    ));
    assert!(terminal_service_credential(CasService::Library, &over).is_err());
    let over_fragment = url(&format!(
        "{BOOKING_ORIGIN}/v4/login/cas#cas={}",
        "a".repeat(4097)
    ));
    assert!(terminal_service_credential(CasService::Library, &over_fragment).is_err());
}

#[test]
fn library_terminal_credential_refuses_malformed_or_duplicated_values() {
    for input in [
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a&cas=b",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a&cas=a",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=&cas=",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a&%63as=b",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a%0Ab",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a%09b",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=%00a",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=%7Fa",
        // Blank, duplicated or control-bearing values refuse identically in
        // the fragment, and a duplicate across query and fragment refuses.
        "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=",
        "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=a&cas=b",
        "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=a&cas=a",
        "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=a&%63as=b",
        "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=a%0Ab",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a#cas=b",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a#cas=a",
        "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=a#/route?cas=b",
    ] {
        assert!(credential(CasService::Library, input).is_err(), "{input}");
    }
}

#[test]
fn library_terminal_credential_refuses_foreign_or_shaped_origins() {
    for input in [
        // Admitted-but-wrong origin: sso is in the library policy yet the
        // credential may only leave on the booking origin.
        "https://sso.buaa.edu.cn/login?cas=ST-synthetic",
        // Foreign relying parties are not admitted for the library profile.
        "https://app.buaa.edu.cn/?cas=ST-synthetic",
        "https://yjapi.msa.buaa.edu.cn/casapi/index.php?cas=ST-synthetic",
        "https://classroom.msa.buaa.edu.cn/?cas=ST-synthetic",
        // Shaped booking origins refuse before any extraction happens.
        "http://booking.lib.buaa.edu.cn/?cas=ST-synthetic",
        "https://operator@booking.lib.buaa.edu.cn/?cas=ST-synthetic",
        "https://operator:secret@booking.lib.buaa.edu.cn/?cas=ST-synthetic",
        "https://booking.lib.buaa.edu.cn:4443/?cas=ST-synthetic",
        "https://booking.lib.buaa.edu.cn./?cas=ST-synthetic",
        "https://sub.booking.lib.buaa.edu.cn/?cas=ST-synthetic",
        "https://booking.lib.buaa.edu.cn.evil.example/?cas=ST-synthetic",
        // A fragment credential on a foreign or shaped origin refuses too:
        // admission of the fragment never widens the origin predicate.
        "https://sso.buaa.edu.cn/login#cas=ST-synthetic",
        "https://app.buaa.edu.cn/#cas=ST-synthetic",
        "https://classroom.msa.buaa.edu.cn/#cas=ST-synthetic",
        "https://booking.lib.buaa.edu.cn.evil.example/#cas=ST-synthetic",
        "https://operator@booking.lib.buaa.edu.cn/#cas=ST-synthetic",
        "https://booking.lib.buaa.edu.cn:4443/#cas=ST-synthetic",
        "http://booking.lib.buaa.edu.cn/#cas=ST-synthetic",
    ] {
        assert!(credential(CasService::Library, input).is_err(), "{input}");
    }

    // The terminal fragment is an extraction carrier only: the same URL is
    // still inadmissible as a request target in every profile.
    let fragmented = url("https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-synthetic");
    for service in ALL_SERVICES {
        assert!(!allowed(&fragmented, service));
    }
}

#[test]
fn non_library_profiles_never_release_the_library_credential() {
    // A `cas` pair on a profile's own admitted origin yields no credential.
    for (service, input) in [
        (
            CasService::Classroom,
            "https://sso.buaa.edu.cn/login?cas=ST-synthetic",
        ),
        (
            CasService::Classroom,
            "https://yjapi.msa.buaa.edu.cn/casapi/index.php?cas=ST-synthetic",
        ),
        (
            CasService::Classroom,
            "https://classroom.msa.buaa.edu.cn/?cas=ST-synthetic",
        ),
        (
            CasService::SmartClassrooms,
            "https://sso.buaa.edu.cn/login?cas=ST-synthetic",
        ),
        (
            CasService::SmartClassrooms,
            "https://app.buaa.edu.cn/a_buaa/api/cas/index?cas=ST-synthetic",
        ),
        (
            CasService::Ihome,
            "https://sso.buaa.edu.cn/login?cas=ST-synthetic",
        ),
        (
            CasService::Ihome,
            "https://i.buaa.edu.cn/api/authLogin?cas=ST-synthetic",
        ),
    ] {
        assert!(matches!(credential(service, input), Ok(None)), "{input}");
    }
}

#[test]
fn ihome_terminal_credential_binds_only_the_web_fragment_token() {
    // The reviewed terminal shape: http or https platform URL on the exact
    // /web/ prefix whose fragment carries a unique type=0 and one nonempty
    // token. The router prefix before the fragment parameters is the
    // source's own detail and is not required.
    for (input, expected) in [
        (
            "http://i.buaa.edu.cn/web/#/login?type=0&token=synthetic-ihome-token",
            "synthetic-ihome-token",
        ),
        (
            "https://i.buaa.edu.cn/web/#/login?type=0&token=synthetic-ihome-token",
            "synthetic-ihome-token",
        ),
        ("http://i.buaa.edu.cn/web/#?type=0&token=abc", "abc"),
        ("http://i.buaa.edu.cn/web/#/login?token=abc&type=0", "abc"),
        ("http://i.buaa.edu.cn/web/#/login?type=0&token=a%20b", "a b"),
        (
            "http://i.buaa.edu.cn/web/#/login?type=0&token=t&from=wap",
            "t",
        ),
        (
            "http://i.buaa.edu.cn/web/#/login?%74ype=0&%74oken=enc",
            "enc",
        ),
        (
            "https://i.buaa.edu.cn/web/?from=wap#/login?type=0&token=routed",
            "routed",
        ),
    ] {
        let value = credential(CasService::Ihome, input)
            .expect("admissible terminal")
            .expect("credential present");
        assert_eq!(value.as_str(), expected, "{input}");
    }

    // Non-credential URLs on the platform host and foreign hosts bind no
    // iHome token; the ordinary origin predicate decides their fate.
    for input in [
        "https://i.buaa.edu.cn/",
        "https://i.buaa.edu.cn/api/authLogin",
        "https://i.buaa.edu.cn/other/#/route?type=0&token=t",
        "https://i.buaa.edu.cn/web/",
        "https://sso.buaa.edu.cn/login#/route?type=0&token=t",
        "https://app.buaa.edu.cn/#/login?type=0&token=t",
    ] {
        assert!(
            credential(CasService::Ihome, input)
                .expect("admissible url")
                .is_none(),
            "{input}"
        );
    }

    // The bound is inclusive; one byte past it refuses.
    let bounded = url(&format!(
        "http://i.buaa.edu.cn/web/#/login?type=0&token={}",
        "a".repeat(4096)
    ));
    let bounded = terminal_service_credential(CasService::Ihome, &bounded)
        .expect("bounded value")
        .expect("credential");
    assert_eq!(bounded.as_str().len(), 4096);
    let over = url(&format!(
        "http://i.buaa.edu.cn/web/#/login?type=0&token={}",
        "a".repeat(4097)
    ));
    assert!(terminal_service_credential(CasService::Ihome, &over).is_err());
}

#[test]
fn ihome_terminal_credential_refuses_malformed_or_ambiguous_fragments() {
    for input in [
        // A fragment without terminal parameters is never a credential.
        "http://i.buaa.edu.cn/web/#/login",
        "http://i.buaa.edu.cn/web/#from=wap",
        // Exactly one type=0 and one nonempty token are both required.
        "http://i.buaa.edu.cn/web/#/login?type=0",
        "http://i.buaa.edu.cn/web/#/login?token=t",
        "http://i.buaa.edu.cn/web/#/login?type=0&token=",
        "http://i.buaa.edu.cn/web/#/login?type=&token=t",
        "http://i.buaa.edu.cn/web/#/login?type=1&token=t",
        "http://i.buaa.edu.cn/web/#/login?type=00&token=t",
        // Duplicated names refuse, including across percent spellings.
        "http://i.buaa.edu.cn/web/#/login?type=0&token=a&token=b",
        "http://i.buaa.edu.cn/web/#/login?type=0&token=a&%74oken=b",
        "http://i.buaa.edu.cn/web/#/login?type=0&type=0&token=t",
        // Control-bearing values refuse.
        "http://i.buaa.edu.cn/web/#/login?type=0&token=a%0Ab",
        "http://i.buaa.edu.cn/web/#/login?type=0&token=a%09b",
        "http://i.buaa.edu.cn/web/#/login?type=0&token=%00a",
        "http://i.buaa.edu.cn/web/#/login?type=0&token=%7Fa",
        // Credential names outside the fragment are ambiguous with the
        // reviewed contract and refuse, even beside a valid fragment.
        "http://i.buaa.edu.cn/web/?type=0&token=t",
        "http://i.buaa.edu.cn/web/?token=t#/login?type=0&token=t",
        "http://i.buaa.edu.cn/web/?type=0#/login?type=0&token=t",
    ] {
        assert!(credential(CasService::Ihome, input).is_err(), "{input}");
    }
}

#[test]
fn ihome_terminal_credential_refuses_shaped_platform_origins() {
    // A matching platform host with a shaped origin refuses before any
    // extraction happens.
    for input in [
        "http://operator@i.buaa.edu.cn/web/#/login?type=0&token=t",
        "http://operator:secret@i.buaa.edu.cn/web/#/login?type=0&token=t",
        "https://i.buaa.edu.cn:4443/web/#/login?type=0&token=t",
        "ftp://i.buaa.edu.cn/web/#/login?type=0&token=t",
    ] {
        assert!(credential(CasService::Ihome, input).is_err(), "{input}");
    }
    // Lookalike hosts are simply not the platform host: no token binds and
    // the origin predicate refuses the follow.
    for input in [
        "http://i.buaa.edu.cn./web/#/login?type=0&token=t",
        "http://sub.i.buaa.edu.cn/web/#/login?type=0&token=t",
        "http://i.buaa.edu.cn.evil.example/web/#/login?type=0&token=t",
        "http://ihome.buaa.edu.cn/web/#/login?type=0&token=t",
    ] {
        assert!(
            credential(CasService::Ihome, input)
                .expect("admissible url")
                .is_none(),
            "{input}"
        );
    }
}

#[test]
fn non_ihome_profiles_never_release_the_terminal_token() {
    let terminal = "https://i.buaa.edu.cn/web/#/login?type=0&token=t";
    // The platform origin is refused outright outside the iHome profile; a
    // well-formed terminal token never leaks across profiles.
    for service in [
        CasService::Classroom,
        CasService::SmartClassrooms,
        CasService::Library,
    ] {
        assert!(credential(service, terminal).is_err());
    }
    // Other parties' terminal shapes never bind for the iHome profile.
    assert!(!matches!(
        credential(
            CasService::Ihome,
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-synthetic"
        ),
        Ok(Some(_))
    ));
    assert!(matches!(
        credential(
            CasService::Ihome,
            "https://app.buaa.edu.cn/web/#/login?type=0&token=t"
        ),
        Ok(None)
    ));
}

#[test]
fn ihome_plaintext_callback_upgrades_only_the_exact_reviewed_shape() {
    let upgraded = |input: &str| upgraded_service_callback(CasService::Ihome, &url(input));

    // The declared plaintext callback is upgraded to its HTTPS spelling with
    // every other component preserved; the ticket travels encrypted.
    let candidate = upgraded("http://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic")
        .expect("the reviewed callback upgrades");
    assert_eq!(
        candidate.as_str(),
        "https://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic"
    );
    assert_eq!(
        upgraded("http://i.buaa.edu.cn/api/authLogin")
            .expect("upgrade without query")
            .as_str(),
        "https://i.buaa.edu.cn/api/authLogin"
    );

    // Every shaping refuses the upgrade and keeps the plaintext scheme, so
    // the origin predicate refuses the follow.
    for input in [
        "http://i.buaa.edu.cn/api/authLogin/",
        "http://i.buaa.edu.cn/api/authLogin/extra",
        "http://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic#fragment",
        "http://i.buaa.edu.cn:8080/api/authLogin?ticket=ST-synthetic",
        "http://operator@i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic",
        "http://operator:secret@i.buaa.edu.cn/api/authLogin",
        "http://i.buaa.edu.cn./api/authLogin",
        "http://i.buaa.edu.cn.evil.example/api/authLogin",
        "http://ihome.buaa.edu.cn/api/authLogin",
        "http://i.buaa.edu.cn/web/",
        "http://i.buaa.edu.cn/",
        // Already-HTTPS and non-iHome URLs are never rewritten.
        "https://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic",
        "http://app.buaa.edu.cn/api/authLogin",
        "http://booking.lib.buaa.edu.cn/api/authLogin",
    ] {
        assert!(upgraded(input).is_none(), "{input}");
    }
    for service in [
        CasService::Classroom,
        CasService::SmartClassrooms,
        CasService::Library,
    ] {
        assert!(
            upgraded_service_callback(
                service,
                &url("http://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic")
            )
            .is_none(),
            "another service must never adopt the iHome callback"
        );
    }
}

// ---------------------------------------------------------------------------
// Strict-TLS local CAS flows. An ephemeral CA signs one leaf covering the
// three synthetic relying-party SANs; the client pins only that CA and
// resolves each host to its own loopback listener. Nothing is relaxed: no
// invalid-certificate acceptance, no production trust or environment change.
// ---------------------------------------------------------------------------

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::X509;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// One observed request never exceeds this many bytes, headers included.
const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// A synthetic CAS sign-on page. The form posts to the selected relying
/// party's pinned route and carries only reviewed fields.
fn service_login_page(service: CasService) -> String {
    let action = pinned(service).as_str().replace('&', "&amp;");
    format!(
        r#"<html><body>
<form method="post" id="loginForm" action="{action}">
<input name="username" type="text">
<input name="password" type="password">
<input name="submit" type="submit" value="LOGIN">
<input name="type" type="hidden" value="username_password">
<input name="execution" type="hidden" value="synthetic-execution-token">
<input name="_eventId" type="hidden" value="submit">
</form>
</body></html>"#
    )
}

struct TestPki {
    ca_pem: Vec<u8>,
    leaf_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

fn test_pki() -> TestPki {
    let rsa = Rsa::generate(2048).expect("rsa key");
    let key = PKey::from_rsa(rsa).expect("pkey");
    let serial = || {
        let mut serial = BigNum::new().expect("bignum");
        serial
            .rand(64, MsbOption::MAYBE_ZERO, false)
            .expect("serial");
        serial.to_asn1_integer().expect("asn1 serial")
    };
    let mut name = openssl::x509::X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", "buaa-cli synthetic test CA")
        .expect("ca name");
    let name = name.build();
    let mut ca_builder = X509::builder().expect("ca builder");
    ca_builder.set_version(2).expect("version");
    ca_builder.set_serial_number(&serial()).expect("serial");
    ca_builder.set_subject_name(&name).expect("ca subject");
    ca_builder.set_issuer_name(&name).expect("ca issuer");
    ca_builder.set_pubkey(&key).expect("ca pubkey");
    let not_before = Asn1Time::days_from_now(0).expect("not before");
    ca_builder.set_not_before(&not_before).expect("not before");
    let not_after = Asn1Time::days_from_now(1).expect("not after");
    ca_builder.set_not_after(&not_after).expect("not after");
    ca_builder
        .append_extension(BasicConstraints::new().critical().ca().build().expect("bc"))
        .expect("ca constraints");
    ca_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("ca key usage"),
        )
        .expect("ca usage");
    ca_builder
        .sign(&key, MessageDigest::sha256())
        .expect("ca sign");
    let ca = ca_builder.build();

    let mut leaf_name = openssl::x509::X509NameBuilder::new().expect("leaf name");
    leaf_name
        .append_entry_by_text("CN", "sso.buaa.edu.cn")
        .expect("leaf cn");
    let leaf_name = leaf_name.build();
    let mut leaf = X509::builder().expect("leaf builder");
    leaf.set_version(2).expect("version");
    leaf.set_serial_number(&serial()).expect("serial");
    leaf.set_subject_name(&leaf_name).expect("leaf subject");
    leaf.set_issuer_name(ca.subject_name())
        .expect("leaf issuer");
    leaf.set_pubkey(&key).expect("leaf pubkey");
    leaf.set_not_before(&not_before).expect("not before");
    leaf.set_not_after(&not_after).expect("not after");
    let san = SubjectAlternativeName::new()
        .dns("sso.buaa.edu.cn")
        .dns("app.buaa.edu.cn")
        .dns("booking.lib.buaa.edu.cn")
        .dns("i.buaa.edu.cn")
        .build(&leaf.x509v3_context(Some(&ca), None))
        .expect("san");
    leaf.append_extension(san).expect("leaf san");
    leaf.append_extension(BasicConstraints::new().critical().build().expect("leaf bc"))
        .expect("leaf constraints");
    leaf.sign(&key, MessageDigest::sha256()).expect("leaf sign");
    let leaf = leaf.build();
    TestPki {
        ca_pem: ca.to_pem().expect("ca pem"),
        leaf_pem: leaf.to_pem().expect("leaf pem"),
        key_pem: key.private_key_to_pem_pkcs8().expect("key pem"),
    }
}

#[derive(Debug)]
struct ObservedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl ObservedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_http_request(stream: &mut openssl::ssl::SslStream<TcpStream>) -> Option<ObservedRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() > MAX_REQUEST_BYTES {
            return None;
        }
        let read = std::io::Read::read(stream, &mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name, value));
    }
    // A declared length is a claim, not a limit: an oversized body is
    // refused instead of buffered.
    if content_length > MAX_REQUEST_BYTES {
        return None;
    }
    while bytes.len() - header_end < content_length {
        let read = std::io::Read::read(stream, &mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let body =
        String::from_utf8_lossy(&bytes[header_end..header_end + content_length]).into_owned();
    Some(ObservedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn http_response(status: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");
    response.push_str(body);
    response.into_bytes()
}

/// One loopback TLS endpoint standing in for one synthetic campus host. The
/// worker is bounded: the listener polls a stop flag and each connection is
/// served once with read timeouts, so a failed test never strands a thread.
struct CasEndpoint {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl CasEndpoint {
    fn start(
        acceptor: Arc<SslAcceptor>,
        responder: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_requests, worker_stop) = (Arc::clone(&requests), Arc::clone(&stop));
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        let mut tls = match acceptor.accept(stream) {
                            Ok(tls) => tls,
                            Err(_) => continue,
                        };
                        let Some(request) = read_http_request(&mut tls) else {
                            continue;
                        };
                        let response = responder(&request);
                        worker_requests.lock().expect("request log").push(request);
                        let _ = std::io::Write::write_all(&mut tls, &response);
                        let _ = tls.shutdown();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn observed(&self) -> Vec<ObservedRequest> {
        self.requests
            .lock()
            .expect("request log")
            .iter()
            .map(|request| ObservedRequest {
                method: request.method.clone(),
                target: request.target.clone(),
                headers: request.headers.clone(),
                body: request.body.clone(),
            })
            .collect()
    }
}

impl Drop for CasEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn tls_acceptor(pki: &TestPki) -> Arc<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("tls acceptor");
    builder
        .set_private_key(&PKey::private_key_from_pem(&pki.key_pem).expect("key"))
        .expect("acceptor key");
    builder
        .set_certificate(&X509::from_pem(&pki.leaf_pem).expect("leaf"))
        .expect("acceptor cert");
    builder
        .add_extra_chain_cert(X509::from_pem(&pki.ca_pem).expect("ca"))
        .expect("chain");
    builder.check_private_key().expect("key pair");
    Arc::new(builder.build())
}

fn strict_client(pki: &TestPki, endpoints: &[(&str, SocketAddr)]) -> Client {
    let mut builder = Client::builder()
        .user_agent("buaa-cli/0.1")
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_only()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .https_only(true)
        .add_root_certificate(reqwest::Certificate::from_pem(&pki.ca_pem).expect("pinned ca"));
    for (host, address) in endpoints {
        builder = builder.resolve(host, *address);
    }
    builder.build().expect("strict test client")
}

/// Unique suffixes for the private governor directories of this test binary.
static GOVERNOR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A private governor directory that is removed when the test ends. The
/// directory is always created new: no pre-existing content is ever
/// deleted, and the guard is released only after the governor and its lease
/// descriptors are gone.
struct GovernorDir {
    path: std::path::PathBuf,
    _directory: File,
}

impl Drop for GovernorDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn service_test_governor(name: &str) -> (GovernorDir, Governor) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "buaa-cli-smart-test-{}-{name}-{}",
        std::process::id(),
        GOVERNOR_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("private governor directory");
    let directory = crate::governor::open_directory(&path, true, true).expect("pinned directory");
    let governor = Governor::isolated_for_test(&path).expect("isolated governor");
    (
        GovernorDir {
            path,
            _directory: directory,
        },
        governor,
    )
}

fn finish_lease(lease: RequestLease<'_>, error: Option<&Error>) {
    let outcome = match error {
        None => crate::governor::Outcome::Http {
            status: 200,
            retry_after: None,
            challenge: false,
            network_failure: false,
        },
        Some(error) if error.code == "auth_latched" => crate::governor::Outcome::CredentialRejected,
        Some(_) => crate::governor::Outcome::NetworkFailure,
    };
    lease.finish(outcome).expect("durable lease finish");
}

struct CasHarness {
    // Dropped first so no in-flight client connection can strand a worker
    // read when the endpoints are stopped and joined.
    client: Client,
    sso: CasEndpoint,
    app: CasEndpoint,
    booking: CasEndpoint,
    ihome: CasEndpoint,
}

impl CasHarness {
    /// Serve the pinned sign-on page, redirect the credential POST to
    /// `cas_landing`, and expose per-host request logs for assertions.
    fn new(service: CasService, cas_landing: &str) -> Self {
        Self::with_responders(
            sso_responder(service, cas_landing, &[]),
            |_| {
                http_response(
                    "200 OK",
                    &[
                        ("Content-Type", "text/html"),
                        (
                            "Set-Cookie",
                            "smart_session=synthetic-app-session; Domain=app.buaa.edu.cn; Path=/; Secure; HttpOnly",
                        ),
                    ],
                    "<html><body>landing</body></html>",
                )
            },
            |_| http_response("200 OK", &[("Content-Type", "text/plain")], "unexpected"),
        )
    }

    /// Serve the pinned sign-on page and let each host answer with its own
    /// responder, so a flow can drive the exact hops it expects.
    fn with_responders(
        sso: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
        app: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
        booking: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
    ) -> Self {
        Self::with_service_responders(sso, app, booking, |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        })
    }

    /// The full four-host stand-in including the platform endpoint, so an
    /// iHome flow can serve its CAS callback and its one business read.
    fn with_service_responders(
        sso: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
        app: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
        booking: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
        ihome: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static,
    ) -> Self {
        let pki = test_pki();
        let acceptor = tls_acceptor(&pki);
        let sso = CasEndpoint::start(Arc::clone(&acceptor), sso);
        let app = CasEndpoint::start(Arc::clone(&acceptor), app);
        let booking = CasEndpoint::start(Arc::clone(&acceptor), booking);
        let ihome = CasEndpoint::start(acceptor, ihome);
        let client = strict_client(
            &pki,
            &[
                ("sso.buaa.edu.cn", sso.address),
                ("app.buaa.edu.cn", app.address),
                ("booking.lib.buaa.edu.cn", booking.address),
                ("i.buaa.edu.cn", ihome.address),
            ],
        );
        Self {
            client,
            sso,
            app,
            booking,
            ihome,
        }
    }
}

/// Serve the synthetic sign-on page and answer the credential POST with a
/// redirect to the reviewed relying party. `post_headers` adds response
/// headers to that redirect, so a deferred sign-on can be reproduced.
fn sso_responder(
    service: CasService,
    cas_landing: &str,
    post_headers: &[(&str, &str)],
) -> impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static {
    let page = service_login_page(service);
    let landing = cas_landing.to_owned();
    let extra: Vec<(String, String)> = post_headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    move |request| {
        if request.method == "GET" && request.target.starts_with("/login") {
            return http_response(
                "200 OK",
                &[
                    ("Content-Type", "text/html"),
                    (
                        "Set-Cookie",
                        "CASTGC=host-only-credential; Path=/; Secure; HttpOnly",
                    ),
                ],
                &page,
            );
        }
        if request.method == "POST" && request.target.starts_with("/login") {
            let mut headers: Vec<(&str, &str)> = vec![("Location", landing.as_str())];
            headers.extend(
                extra
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            );
            return http_response("302 Found", &headers, "");
        }
        http_response(
            "404 Not Found",
            &[("Content-Type", "text/plain")],
            "unexpected",
        )
    }
}

/// The decoded query pairs of an observed target.
fn query_map(target: &Url) -> BTreeMap<String, String> {
    target
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// The absolute URL of an observed request on its synthetic campus host.
fn observed_url(host: &str, request: &ObservedRequest) -> Url {
    url(&format!("https://{host}{}", request.target))
}

/// The sign-on exchange submits the credential exactly once, to the pinned
/// route of the selected relying party, with the reviewed form fields and
/// nothing else.
fn assert_one_credential_post(harness: &CasHarness, service: CasService) {
    let requests = harness.sso.observed();
    assert_eq!(requests.len(), 2, "GET form + one credential POST");
    let pinned = pinned(service);
    let expected_route = query_map(&pinned);
    let form = &requests[0];
    assert_eq!(form.method, "GET");
    let form_url = observed_url("sso.buaa.edu.cn", form);
    assert_eq!(form_url.path(), pinned.path());
    assert_eq!(
        query_map(&form_url),
        expected_route,
        "the sign-on route must name the selected relying party"
    );
    let post = &requests[1];
    assert_eq!(post.method, "POST");
    let post_url = observed_url("sso.buaa.edu.cn", post);
    assert_eq!(post_url.path(), pinned.path());
    assert_eq!(
        query_map(&post_url),
        expected_route,
        "the credential must post to the same route"
    );
    assert_eq!(post.header("referer"), Some(pinned.as_str()));
    assert_eq!(
        post.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    // Exactly one credential submission, with the reviewed fields only.
    let fields: BTreeMap<String, String> = ::url::form_urlencoded::parse(post.body.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let expected_fields = BTreeMap::from([
        ("username".to_string(), SESSION_USERNAME.to_string()),
        ("password".to_string(), SESSION_PASSWORD.to_string()),
        ("submit".to_string(), "LOGIN".to_string()),
        ("type".to_string(), "username_password".to_string()),
        (
            "execution".to_string(),
            "synthetic-execution-token".to_string(),
        ),
        ("_eventId".to_string(), "submit".to_string()),
    ]);
    assert_eq!(fields, expected_fields, "unexpected credential POST body");
    assert_eq!(post.body.matches("username=").count(), 1);
    assert_eq!(post.body.matches("password=").count(), 1);
}

#[test]
fn smart_classroom_flow_leaves_scoped_cookie_without_leaking_sso_credential() {
    let harness = CasHarness::new(
        CasService::SmartClassrooms,
        "https://app.buaa.edu.cn/site/classRoomQuery/index",
    );
    let (_guard, governor) = service_test_governor("smart-flow");
    let mut lease = governor
        .try_acquire(RequestKind::Authentication)
        .expect("authentication lease");
    let credentials =
        SsoCredentials::new(SESSION_USERNAME, SESSION_PASSWORD).expect("synthetic credentials");
    let result = authenticate_service(
        &mut lease,
        &harness.client,
        CasService::SmartClassrooms,
        credentials,
    );
    finish_lease(lease, result.as_ref().err());
    let mut session = result.expect("smart CAS flow");

    assert_one_credential_post(&harness, CasService::SmartClassrooms);

    // The relying-party callback and landing never see the sign-on cookie:
    // CASTGC is host-only for sso.buaa.edu.cn.
    let app_requests = harness.app.observed();
    assert_eq!(app_requests.len(), 1);
    assert_eq!(app_requests[0].method, "GET");
    assert_eq!(app_requests[0].header("host"), Some("app.buaa.edu.cn"));
    let app_cookie = app_requests[0].header("cookie").unwrap_or("");
    assert!(!app_cookie.contains("CASTGC"), "{app_cookie}");

    // The terminal handoff exposes only the app-scoped session cookie.
    let probe = url("https://app.buaa.edu.cn/buaafreeclass/wap/default/search1");
    let (cookie, _expiry) = session.cookie_header(&probe).expect("scoped cookie view");
    let cookie = cookie.expect("app cookie present");
    assert!(cookie.contains(SMART_APP_COOKIE), "{}", cookie.as_str());
    assert!(!cookie.contains("CASTGC"), "{}", cookie.as_str());

    // Nothing reached the library origin and no library credential exists.
    assert!(harness.booking.observed().is_empty());
    assert!(
        session
            .cookie_header(&url("https://booking.lib.buaa.edu.cn/"))
            .is_err()
    );
    assert!(session.take_service_credential().is_err());
}

#[test]
fn library_flow_consumes_terminal_fragment_cas_without_requesting_it() {
    let harness = CasHarness::new(
        CasService::Library,
        "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
    );
    let (_guard, governor) = service_test_governor("library-flow");
    let mut lease = governor
        .try_acquire(RequestKind::Authentication)
        .expect("authentication lease");
    let credentials =
        SsoCredentials::new(SESSION_USERNAME, SESSION_PASSWORD).expect("synthetic credentials");
    let result = authenticate_service(
        &mut lease,
        &harness.client,
        CasService::Library,
        credentials,
    );
    finish_lease(lease, result.as_ref().err());
    let mut session = result.expect("library CAS flow");

    assert_one_credential_post(&harness, CasService::Library);

    // The fragment CAS is a terminal in-memory handoff: it is never fetched.
    assert!(
        harness.booking.observed().is_empty(),
        "the terminal credential URL must never be requested"
    );
    assert!(harness.app.observed().is_empty());

    let cas = session.take_service_credential().expect("terminal cas");
    assert_eq!(cas.as_str(), SMART_CAS_VALUE);
    // The credential is consumed exactly once; no retry materializes one.
    assert!(session.take_service_credential().is_err());

    // The library origin gained no cookie and the host-only sign-on
    // credential never appears through the scoped view.
    let (cookie, _expiry) = session
        .cookie_header(&url("https://booking.lib.buaa.edu.cn/"))
        .expect("library scoped view");
    assert!(cookie.is_none());
}

// ---------------------------------------------------------------------------
// Smart session flows: one in-memory CAS login plus exactly one business
// read. The same strict-TLS loopback stand-in serves every hop, the
// governor is an isolated private one, and the network factory is the only
// route to the network, so a flow that must stay local can prove it never
// consulted it.
// ---------------------------------------------------------------------------

/// The typed one-shot session envelope. The read carries no authentication
/// material: the session derives its own credential from the sign-on.
fn session_input(service: &str, read: Value) -> String {
    json!({
        "authorized": true,
        "username": SESSION_USERNAME,
        "password": SESSION_PASSWORD,
        "intent": format!("LOGIN {SESSION_USERNAME} smart {service}"),
        "read": read,
    })
    .to_string()
}

fn classrooms_read() -> Value {
    json!({"service": "classrooms", "enabled": true, "campus_id": 3, "date": "2031-04-12"})
}

fn library_read() -> Value {
    json!({"service": "library", "enabled": true,
           "query": {"operation": "premises", "day": "2031-04-12"}})
}

/// Run one session flow against the loopback stand-in with an isolated
/// governor. The flag records whether the network factory was consulted.
fn run_session(harness: &CasHarness, input: &str, name: &str) -> (Result<Value, Error>, bool) {
    let (guard, governor) = service_test_governor(name);
    let client = harness.client.clone();
    let mut factory_used = false;
    let result = crate::smart::session_with_network(input, true, || {
        factory_used = true;
        Ok((client, governor))
    });
    // The governor is released inside the call; the private directory guard
    // is dropped only afterwards.
    drop(guard);
    (result, factory_used)
}

/// Run a session flow that must never reach the network. The factory would
/// fail loudly if it were consulted.
fn run_offline_session(input: &str, online: bool) -> (Result<Value, Error>, bool) {
    let mut factory_used = false;
    let result = crate::smart::session_with_network(input, online, || {
        factory_used = true;
        Err(Error::new(
            "network_factory_consulted",
            "the network factory was consulted",
        ))
    });
    (result, factory_used)
}

/// Serve the classroom landing and the one business read it authorizes.
fn classroom_app_responder(
    search: &'static str,
) -> impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static {
    move |request| {
        let path = request.target.split('?').next().unwrap_or("");
        match path {
            "/site/classRoomQuery/index" => http_response(
                "200 OK",
                &[
                    ("Content-Type", "text/html"),
                    (
                        "Set-Cookie",
                        "smart_session=synthetic-app-session; Domain=app.buaa.edu.cn; Path=/; Secure; HttpOnly",
                    ),
                ],
                "<html><body>landing</body></html>",
            ),
            "/buaafreeclass/wap/default/search1" => {
                http_response("200 OK", &[("Content-Type", "application/json")], search)
            }
            _ => http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            ),
        }
    }
}

/// Serve the one CAS exchange and the one business read it authorizes.
fn library_responder(
    login: &'static str,
    read: &'static str,
) -> impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static {
    library_responder_with_cookies(login, read, &LIBRARY_COOKIES)
}

/// The cookies the library exchange issues: a path-scoped sign-on cookie that
/// never reaches the business read, and the scoped session cookie it does.
const LIBRARY_COOKIES: [&str; 2] = [
    "login_sid=auth-private; Path=/v4/login; Secure; HttpOnly",
    "lib_session=synthetic-library-session; Domain=booking.lib.buaa.edu.cn; Path=/; Secure; HttpOnly",
];

/// A sign-on cookie that is issued twice: the second issuance replaces the
/// first value.
const REPLACED_LIBRARY_COOKIES: [&str; 2] = [
    "login_sid=auth-private-alpha; Path=/v4/login; Secure; HttpOnly",
    "login_sid=auth-private-beta; Path=/v4/login; Secure; HttpOnly",
];

/// Serve the one CAS exchange and the one business read it authorizes, with
/// the exact cookie issuances the flow under test needs.
fn library_responder_with_cookies(
    login: &'static str,
    read: &'static str,
    cookies: &'static [&'static str],
) -> impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static {
    move |request| {
        let path = request.target.split('?').next().unwrap_or("");
        match path {
            "/v4/login/user" => {
                let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
                for cookie in cookies {
                    headers.push(("Set-Cookie", *cookie));
                }
                http_response("200 OK", &headers, login)
            }
            "/v4/space/pcTopFor" => {
                http_response("200 OK", &[("Content-Type", "application/json")], read)
            }
            _ => http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            ),
        }
    }
}

#[test]
fn smart_session_classrooms_logs_in_once_and_projects_the_real_search_result() {
    let search = r#"{"e":0,"d":{"list":{"BuildingA":[{"kxsds":"1,2,3","roomName":"101"}]}}}"#;
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::SmartClassrooms,
            "https://app.buaa.edu.cn/site/classRoomQuery/index",
            &[],
        ),
        classroom_app_responder(search),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, factory_used) = run_session(
        &harness,
        &session_input("classrooms", classrooms_read()),
        "session-classrooms",
    );
    assert!(
        factory_used,
        "an online session consults the network factory"
    );
    let output = result.expect("smart session result");
    assert_eq!(output["service"], "classrooms");
    assert_eq!(output["result"], "ok");
    assert_eq!(output["source"], "network");
    assert_eq!(output["network_performed"], true);
    assert_eq!(output["write_operations_performed"], false);
    let rows = output["data"].as_array().expect("projected room rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["building"], "BuildingA");
    assert_eq!(rows[0]["free_periods"], json!([1, 2, 3]));
    assert_eq!(rows[0]["roomName"], "101");
    // No credential material reaches the projection.
    let projected = output.to_string();
    for secret in [
        SESSION_USERNAME,
        SESSION_PASSWORD,
        "CASTGC",
        "host-only-credential",
    ] {
        assert!(
            !projected.contains(secret),
            "{secret} leaked into the Smart projection"
        );
    }

    assert_one_credential_post(&harness, CasService::SmartClassrooms);
    let app_requests = harness.app.observed();
    assert_eq!(app_requests.len(), 2, "one landing and one business read");
    let landing = &app_requests[0];
    assert_eq!(landing.method, "GET");
    assert_eq!(
        observed_url("app.buaa.edu.cn", landing).path(),
        "/site/classRoomQuery/index"
    );
    assert!(
        landing.header("cookie").is_none(),
        "the host-only sign-on cookie never leaves its host"
    );
    let read = &app_requests[1];
    assert_eq!(read.method, "GET");
    let target = observed_url("app.buaa.edu.cn", read);
    assert_eq!(target.path(), "/buaafreeclass/wap/default/search1");
    let query = query_map(&target);
    assert_eq!(query.get("xqid").map(String::as_str), Some("3"));
    assert_eq!(query.get("date").map(String::as_str), Some("2031-04-12"));
    assert_eq!(query.get("floorid").map(String::as_str), Some(""));
    assert_eq!(query.len(), 3, "only the reviewed query fields");
    let cookie = read.header("cookie").unwrap_or("");
    assert!(cookie.contains(SMART_APP_COOKIE), "{cookie}");
    assert!(!cookie.contains("CASTGC"), "{cookie}");
    assert_eq!(
        read.header("referer"),
        Some("https://app.buaa.edu.cn/site/classRoomQuery/index")
    );
    // A classroom session never touches the library origin.
    assert!(harness.booking.observed().is_empty());
}

#[test]
fn smart_session_library_exchanges_the_cas_once_and_reads_with_the_issued_token() {
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::Library,
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
            &[],
        ),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        library_responder(
            r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
            r#"{"code":0,"data":{"list":[{"id":"area-1","name":"Area One"}]}}"#,
        ),
    );
    let (result, factory_used) = run_session(
        &harness,
        &session_input("library", library_read()),
        "session-library",
    );
    assert!(
        factory_used,
        "an online session consults the network factory"
    );
    let output = result.expect("smart session result");
    assert_eq!(output["service"], "library");
    assert_eq!(output["result"], "ok");
    assert_eq!(output["source"], "network");
    assert_eq!(output["network_performed"], true);
    assert_eq!(
        output["data"],
        json!([{"id": "area-1", "name": "Area One"}])
    );
    // Neither the sign-on credential, the exchanged CAS value, the issued
    // token nor the scoped cookie is released.
    let projected = output.to_string();
    for secret in [
        SESSION_USERNAME,
        SESSION_PASSWORD,
        SMART_CAS_VALUE,
        LIBRARY_TOKEN,
        "CASTGC",
        "host-only-credential",
        "lib_session",
    ] {
        assert!(
            !projected.contains(secret),
            "{secret} leaked into the Smart projection"
        );
    }

    assert_one_credential_post(&harness, CasService::Library);
    let requests = harness.booking.observed();
    assert_eq!(requests.len(), 2, "one CAS exchange and one business read");
    let exchange = &requests[0];
    assert_eq!(exchange.method, "POST");
    assert_eq!(exchange.target, "/v4/login/user");
    assert_eq!(exchange.header("content-type"), Some("application/json"));
    let exchange_body: Value = serde_json::from_str(&exchange.body).expect("exchange body");
    assert_eq!(exchange_body, json!({"cas": SMART_CAS_VALUE}));
    assert!(
        exchange.header("authorization").is_none(),
        "the exchange carries no bearer token"
    );
    assert!(
        exchange.header("cookie").is_none(),
        "the exchange carries no scoped cookie yet"
    );
    let read = &requests[1];
    assert_eq!(read.method, "POST");
    assert_eq!(read.target, "/v4/space/pcTopFor");
    let authorization = format!("bearer{LIBRARY_TOKEN}");
    assert_eq!(read.header("authorization"), Some(authorization.as_str()));
    let cookie = read.header("cookie").unwrap_or("");
    assert!(cookie.contains(LIBRARY_APP_COOKIE), "{cookie}");
    assert!(!cookie.contains("CASTGC"), "{cookie}");
    assert!(
        !cookie.contains("login_sid"),
        "the path-scoped sign-on cookie never reaches the business read: {cookie}"
    );
    assert_eq!(read.header("content-type"), Some("application/json"));
    let read_body: Value = serde_json::from_str(&read.body).expect("read body");
    assert_eq!(read_body, json!({"day": "2031-04-12"}));
    // A library session never touches the classroom origin.
    assert!(harness.app.observed().is_empty());
}

#[test]
fn smart_session_library_stops_when_the_issued_token_is_missing_or_rejected() {
    for (name, status, login) in [
        (
            "empty-token",
            "200 OK",
            r#"{"code":0,"data":{"member":{"token":""}}}"#,
        ),
        ("missing-member", "200 OK", r#"{"code":0,"data":{}}"#),
        (
            "rejected-code",
            "200 OK",
            r#"{"code":500,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
        ),
        (
            "null-code",
            "200 OK",
            r#"{"code":null,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
        ),
        (
            "unauthorized",
            "401 Unauthorized",
            r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
        ),
    ] {
        let harness = CasHarness::with_responders(
            sso_responder(
                CasService::Library,
                "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
                &[],
            ),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                match path {
                    "/v4/login/user" => {
                        http_response(status, &[("Content-Type", "application/json")], login)
                    }
                    _ => http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        r#"{"code":0,"data":{"list":[]}}"#,
                    ),
                }
            },
        );
        let (result, _) = run_session(
            &harness,
            &session_input("library", library_read()),
            &format!("session-library-{name}"),
        );
        let error = result.expect_err("a rejected exchange must not read");
        let expected = if status.starts_with("401") {
            "auth_latched"
        } else {
            "authentication_unconfirmed"
        };
        assert_eq!(error.code, expected, "{name}: {}", error.message);
        // The business read is never sent and the exchange is never repeated.
        let requests = harness.booking.observed();
        assert_eq!(
            requests.len(),
            1,
            "{name}: only the CAS exchange may be sent"
        );
        assert_eq!(requests[0].target, "/v4/login/user");
    }
}

#[test]
fn smart_session_stops_on_a_challenged_or_deferred_sign_on() {
    // A challenge on the sign-on page never reaches the credential
    // submission.
    let challenged = CasHarness::with_responders(
        |request| {
            if request.method == "GET" {
                http_response(
                    "200 OK",
                    &[("Content-Type", "text/html"), ("cf-mitigated", "challenge")],
                    "<html><body>landing</body></html>",
                )
            } else {
                http_response(
                    "302 Found",
                    &[(
                        "Location",
                        "https://app.buaa.edu.cn/site/classRoomQuery/index",
                    )],
                    "",
                )
            }
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_session(
        &challenged,
        &session_input("classrooms", classrooms_read()),
        "session-challenge",
    );
    let error = result.expect_err("a challenged sign-on must not read");
    assert_eq!(error.code, "challenge_requires_human");
    // Only the sign-on page was fetched: no credential was submitted and no
    // business request was sent.
    assert_eq!(challenged.sso.observed().len(), 1);
    assert!(challenged.app.observed().is_empty());
    assert!(challenged.booking.observed().is_empty());

    // A deferred redirect is a durable cooldown: it is never followed and
    // never retried.
    let deferred = CasHarness::with_responders(
        sso_responder(
            CasService::SmartClassrooms,
            "https://app.buaa.edu.cn/site/classRoomQuery/index",
            &[("Retry-After", "60")],
        ),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_session(
        &deferred,
        &session_input("classrooms", classrooms_read()),
        "session-deferred",
    );
    let error = result.expect_err("a deferred sign-on must not read");
    assert_eq!(error.code, "cooldown", "{}", error.message);
    assert_one_credential_post(&deferred, CasService::SmartClassrooms);
    assert!(
        deferred.app.observed().is_empty(),
        "the deferred redirect is never followed"
    );
    assert!(deferred.booking.observed().is_empty());
}

#[test]
fn smart_session_withholds_a_response_that_echoes_credential_material() {
    for (name, echoed, read) in [
        (
            "cas-value",
            SMART_CAS_VALUE,
            r#"{"code":0,"data":{"list":[{"note":"ST-terminal-synthetic"}]}}"#,
        ),
        (
            "issued-token",
            LIBRARY_TOKEN,
            r#"{"code":0,"data":{"list":[{"note":"synthetic-library-token-7h3k"}]}}"#,
        ),
        (
            "password",
            SESSION_PASSWORD,
            r#"{"code":0,"data":{"list":[{"note":"synthetic-pass"}]}}"#,
        ),
    ] {
        let harness = CasHarness::with_responders(
            sso_responder(
                CasService::Library,
                "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
                &[],
            ),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            library_responder_with_cookies(
                r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
                read,
                &LIBRARY_COOKIES,
            ),
        );
        let (result, _) = run_session(
            &harness,
            &session_input("library", library_read()),
            &format!("session-echo-{name}"),
        );
        let output = result.expect("the business read still settles");
        assert_eq!(output["service"], "library", "{name}");
        assert_eq!(output["result"], "sensitive_response_withheld", "{name}");
        assert_eq!(output["fallback_reason"], "credential_echo", "{name}");
        assert_eq!(output["raw_evidence_withheld"], true, "{name}");
        assert!(
            output.get("data").is_none(),
            "{name}: no business data survives a credential echo"
        );
        assert!(
            !output.to_string().contains(echoed),
            "{name}: the echoed credential was released"
        );
    }
}

#[test]
fn smart_session_never_replays_or_downgrades_a_credential_preserving_redirect() {
    for service in [CasService::SmartClassrooms, CasService::Library] {
        for status in ["307 Temporary Redirect", "308 Permanent Redirect"] {
            let (name, landing, read) = match service {
                CasService::SmartClassrooms => (
                    "classrooms",
                    "https://app.buaa.edu.cn/site/classRoomQuery/index",
                    classrooms_read(),
                ),
                CasService::Library => (
                    "library",
                    "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
                    library_read(),
                ),
                CasService::Classroom | CasService::Ihome | CasService::Byxt
                | CasService::Gsmis | CasService::Boya => unreachable!(),
            };
            let original = sso_responder(service, landing, &[]);
            let harness = CasHarness::with_responders(
                move |request| {
                    if request.method == "POST" {
                        http_response(status, &[("Location", landing)], "")
                    } else {
                        original(request)
                    }
                },
                |_| {
                    http_response(
                        "200 OK",
                        &[("Content-Type", "text/html")],
                        "<html><body>landing</body></html>",
                    )
                },
                library_responder(
                    r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
                    r#"{"code":0,"data":{"list":[]}}"#,
                ),
            );
            let (result, _) = run_session(
                &harness,
                &session_input(name, read),
                &format!("post-redirect-{name}-{status}"),
            );
            assert!(
                result.is_err(),
                "credential-preserving redirects cannot become a new authentication send"
            );
            assert_one_credential_post(&harness, service);
            assert!(harness.app.observed().is_empty());
            assert!(harness.booking.observed().is_empty());
        }
    }
}

#[test]
fn smart_session_refuses_a_challenge_discovered_in_the_landing_body() {
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::SmartClassrooms,
            "https://app.buaa.edu.cn/site/classRoomQuery/index",
            &[],
        ),
        |_| {
            http_response(
                "200 OK",
                &[
                    ("Content-Type", "text/html"),
                    (
                        "Set-Cookie",
                        "smart_session=synthetic-app-session; Path=/; Secure",
                    ),
                ],
                "<html><body><form><label>验证码<input name=\"captcha\"></label></form></body></html>",
            )
        },
        |_| http_response("404 Not Found", &[], "unexpected"),
    );
    let (result, _) = run_session(
        &harness,
        &session_input("classrooms", classrooms_read()),
        "landing-challenge",
    );
    assert_eq!(result.unwrap_err().code, "challenge_requires_human");
    assert_one_credential_post(&harness, CasService::SmartClassrooms);
    let app = harness.app.observed();
    assert_eq!(app.len(), 1, "the challenge prevents the business read");
    assert_eq!(app[0].target, "/site/classRoomQuery/index");
    assert!(harness.booking.observed().is_empty());
}

#[test]
fn smart_session_does_not_invent_a_missing_library_cas_credential() {
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::Library,
            "https://booking.lib.buaa.edu.cn/v4/login/cas",
            &[],
        ),
        |_| http_response("404 Not Found", &[], "unexpected"),
        |_| {
            http_response(
                "200 OK",
                &[("Content-Type", "text/html")],
                "<html><body>landing</body></html>",
            )
        },
    );
    let (result, _) = run_session(
        &harness,
        &session_input("library", library_read()),
        "missing-library-cas",
    );
    assert_eq!(result.unwrap_err().code, "authentication_unconfirmed");
    assert_one_credential_post(&harness, CasService::Library);
    let booking = harness.booking.observed();
    assert_eq!(
        booking.len(),
        1,
        "only the credential-less landing can be fetched"
    );
    assert_eq!(booking[0].method, "GET");
    assert_eq!(booking[0].target, "/v4/login/cas");
    assert!(booking[0].header("cookie").is_none());
    assert!(harness.app.observed().is_empty());
}

#[test]
fn smart_session_stops_instead_of_forgetting_retired_cookie_credentials() {
    let cookies: Vec<String> = (0..MAX_RETIRED_CREDENTIALS + 2)
        .map(|index| format!("login_sid=retired-private-{index}; Path=/v4/login; Secure; HttpOnly"))
        .collect();
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::Library,
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
            &[],
        ),
        |_| http_response("404 Not Found", &[], "unexpected"),
        move |request| {
            if request.target == "/v4/login/user" {
                let mut headers = vec![("Content-Type", "application/json")];
                headers.extend(cookies.iter().map(|value| ("Set-Cookie", value.as_str())));
                http_response(
                    "200 OK",
                    &headers,
                    r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
                )
            } else {
                http_response(
                    "200 OK",
                    &[("Content-Type", "application/json")],
                    r#"{"code":0,"data":{"list":[{"name":"retired-private-0"}]}}"#,
                )
            }
        },
    );
    let (result, _) = run_session(
        &harness,
        &session_input("library", library_read()),
        "cookie-guard-exhaustion",
    );
    assert_eq!(result.unwrap_err().code, "body_limit");
    let booking = harness.booking.observed();
    assert_eq!(
        booking.len(),
        1,
        "no business request after losing a credential guard"
    );
    assert_eq!(booking[0].target, "/v4/login/user");
}

#[test]
fn smart_session_withholds_encoded_complete_cookie_headers() {
    use base64::Engine as _;
    for (service, name, landing, read, cookie) in [
        (
            CasService::SmartClassrooms,
            "classrooms",
            "https://app.buaa.edu.cn/site/classRoomQuery/index",
            classrooms_read(),
            SMART_APP_COOKIE,
        ),
        (
            CasService::Library,
            "library",
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
            library_read(),
            LIBRARY_APP_COOKIE,
        ),
    ] {
        let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
        let class_body =
            json!({"e":0,"d":{"list":{"B":[{"kxsds":"1","roomName":encoded}]}}}).to_string();
        let library_body = json!({"code":0,"data":{"list":[{"note":encoded}]}}).to_string();
        let app = classroom_app_responder("{}");
        let library = library_responder(
            r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
            "{}",
        );
        let harness = CasHarness::with_responders(
            sso_responder(service, landing, &[]),
            move |request| {
                if request
                    .target
                    .starts_with("/buaafreeclass/wap/default/search1?")
                {
                    http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        &class_body,
                    )
                } else {
                    app(request)
                }
            },
            move |request| {
                if request.target == "/v4/space/pcTopFor" {
                    http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        &library_body,
                    )
                } else {
                    library(request)
                }
            },
        );
        let (result, _) = run_session(
            &harness,
            &session_input(name, read),
            &format!("encoded-cookie-{name}"),
        );
        let output = result.unwrap();
        assert_eq!(output["result"], "sensitive_response_withheld");
        assert_eq!(output["fallback_reason"], "credential_echo");
        assert!(output.get("data").is_none());
        assert!(!output.to_string().contains(&encoded));
    }
}

/// The library exchange issues a path-scoped sign-on cookie that never
/// reaches the business read. A business response that echoes its value is
/// still a credential echo and is withheld.
#[test]
fn smart_session_withholds_a_response_that_echoes_the_auth_cookie_value() {
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::Library,
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
            &[],
        ),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        library_responder_with_cookies(
            r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
            r#"{"code":0,"data":{"list":[{"name":"auth-private"}]}}"#,
            &LIBRARY_COOKIES,
        ),
    );
    let (result, _) = run_session(
        &harness,
        &session_input("library", library_read()),
        "session-cookie-echo",
    );
    let output = result.expect("the business read still settles");
    assert_eq!(output["service"], "library");
    assert_eq!(output["result"], "sensitive_response_withheld");
    assert_eq!(output["fallback_reason"], "credential_echo");
    assert_eq!(output["raw_evidence_withheld"], true);
    assert!(
        !output.to_string().contains("auth-private"),
        "the echoed sign-on cookie value was released"
    );
    // The path-scoped sign-on cookie is never delivered to the business read.
    let requests = harness.booking.observed();
    assert_eq!(requests.len(), 2, "one CAS exchange and one business read");
    let read = &requests[1];
    let cookie = read.header("cookie").unwrap_or("");
    assert!(!cookie.contains("login_sid"), "{cookie}");
}

/// A sign-on cookie value that was replaced still belongs to the session: an
/// echo of the replaced value is withheld as well.
#[test]
fn smart_session_withholds_a_response_that_echoes_a_replaced_auth_cookie_value() {
    let harness = CasHarness::with_responders(
        sso_responder(
            CasService::Library,
            "https://booking.lib.buaa.edu.cn/v4/login/cas#cas=ST-terminal-synthetic",
            &[],
        ),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        library_responder_with_cookies(
            r#"{"code":0,"data":{"member":{"token":"synthetic-library-token-7h3k"}}}"#,
            r#"{"code":0,"data":{"list":[{"name":"auth-private-alpha"}]}}"#,
            &REPLACED_LIBRARY_COOKIES,
        ),
    );
    let (result, _) = run_session(
        &harness,
        &session_input("library", library_read()),
        "session-replaced-cookie-echo",
    );
    let output = result.expect("the business read still settles");
    assert_eq!(output["result"], "sensitive_response_withheld");
    assert_eq!(output["fallback_reason"], "credential_echo");
    assert!(
        !output.to_string().contains("auth-private-alpha"),
        "the echoed replaced sign-on cookie value was released"
    );
}

#[test]
fn smart_session_local_refusals_never_consult_the_network_factory() {
    let base = json!({
        "authorized": true,
        "username": SESSION_USERNAME,
        "password": SESSION_PASSWORD,
        "intent": format!("LOGIN {SESSION_USERNAME} smart classrooms"),
        "read": classrooms_read(),
    });
    let mut unauthorized = base.clone();
    unauthorized["authorized"] = json!(false);
    let mut wrong_intent = base.clone();
    wrong_intent["intent"] = json!(format!("LOGIN {SESSION_USERNAME} smart library"));
    let mut extra_field = base.clone();
    extra_field["caller_field"] = json!("surprise");
    let mut caller_token = base.clone();
    caller_token["read"] = json!({"service": "library", "enabled": true,
        "token": "synthetic-caller-token", "query": {"operation": "premises", "day": "2031-04-12"}});
    let mut bad_date = base.clone();
    bad_date["read"] =
        json!({"service": "classrooms", "enabled": true, "campus_id": 3, "date": "2031-13-40"});
    let mut caller_login = base.clone();
    caller_login["read"] = json!({"service": "library", "enabled": true,
        "query": {"operation": "login", "cas": "synthetic-caller-cas"}});
    let mut unsupported = base.clone();
    unsupported["read"] =
        json!({"service": "exams", "enabled": true, "cookie": "synthetic-caller-cookie=9f4e"});

    // A refusal never reproduces the supplied credentials.
    for (name, payload) in [
        ("unauthorized", unauthorized),
        ("wrong-intent", wrong_intent),
        ("invalid-date", bad_date),
        ("caller-login", caller_login),
        ("unsupported-service", unsupported),
    ] {
        let (result, factory_used) = run_offline_session(&payload.to_string(), true);
        let error = result.expect_err(name);
        assert!(
            !factory_used,
            "{name}: the network factory must stay untouched"
        );
        assert!(!error.message.contains(SESSION_PASSWORD), "{name}");
        assert!(!error.message.contains(SESSION_USERNAME), "{name}");
    }
    // Input-schema violations report the input contract itself.
    for (name, payload) in [
        ("unknown-field", extra_field.to_string()),
        ("caller-token", caller_token.to_string()),
        ("malformed-bytes", "not json at all".to_string()),
    ] {
        let (result, factory_used) = run_offline_session(&payload, true);
        let error = result.expect_err(name);
        assert_eq!(error.code, "invalid_input", "{name}: {}", error.message);
        assert!(
            !factory_used,
            "{name}: the network factory must stay untouched"
        );
    }
    // A disabled read is not an error and never opens the network.
    let mut disabled = classrooms_read();
    disabled["enabled"] = json!(false);
    for online in [true, false] {
        let (result, factory_used) =
            run_offline_session(&session_input("classrooms", disabled.clone()), online);
        let output = result.expect("a disabled read is not a refusal");
        assert_eq!(output["result"], "disabled");
        assert_eq!(output["source"], "disabled");
        assert_eq!(output["network_performed"], false);
        assert!(!factory_used);
    }
    // An enabled read without explicit online permission is refused before
    // any authentication attempt.
    let (result, factory_used) =
        run_offline_session(&session_input("classrooms", classrooms_read()), false);
    let error = result.expect_err("an offline session must be refused");
    assert_eq!(error.code, "online_required");
    assert!(!factory_used);
}

// ---------------------------------------------------------------------------
// iHome session flows: one in-memory CAS login plus exactly one business
// read. The reviewed plaintext CAS callback is upgraded to HTTPS for the
// only platform fetch; the terminal fragment token is consumed in memory
// and never requested. Local preflight refusals (disabled, unauthorized,
// offline, invalid selector) are covered by the ihome module's own unit
// regression, so the flows here exercise transport and response safety.
// ---------------------------------------------------------------------------

/// The terminal fragment token the synthetic platform hands over.
const IHOME_TOKEN: &str = "synthetic-ihome-token";
/// The exact terminal fragment URL; it must never be requested.
const IHOME_TERMINAL: &str = "http://i.buaa.edu.cn/web/#/login?type=0&token=synthetic-ihome-token";
/// The plaintext callback the sign-on POST names; it is fetched as HTTPS.
const IHOME_CALLBACK_TICKET: &str = "http://i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic-ihome";
/// A synthetic listing page in the reviewed business envelope.
const IHOME_LIST_BODY: &str = r#"{"code":20000,"success":true,"data":{"current_page":1,"last_page":1,"total":1,"data":[{"id":41,"title":"synthetic appeal title","content":"synthetic appeal content","created_at":"2031-04-12 10:00:00","publish_status_text":"synthetic-status","departments":[{"id":7,"name":"Synthetic Department"}],"appeal_reply":[{"id":9,"department":{"id":7,"name":"Synthetic Department"},"content":"synthetic reply","created_at":"2031-04-12 12:00:00"}]}]}}"#;
/// A synthetic detail page in the reviewed business envelope.
const IHOME_DETAIL_BODY: &str = r#"{"code":20000,"success":true,"data":{"data":{"id":41,"title":"synthetic appeal title","content":"synthetic appeal content","created_at":"2031-04-12 10:00:00","publish_status_text":"synthetic-status","departments":[{"id":7,"name":"Synthetic Department"}],"appeal_reply":[{"id":9,"department":{"id":7,"name":"Synthetic Department"},"content":"synthetic reply","created_at":"2031-04-12 12:00:00"}]}}}"#;

/// The typed one-shot iHome session envelope. The read carries no
/// authentication material: the session derives its own token from the
/// sign-on terminal fragment.
fn ihome_session_input(read: Value) -> String {
    json!({
        "operation": "session",
        "authorized": true,
        "username": SESSION_USERNAME,
        "password": SESSION_PASSWORD,
        "intent": format!("LOGIN {SESSION_USERNAME} ihome"),
        "read": read,
    })
    .to_string()
}

fn ihome_list_read() -> Value {
    json!({"operation": "list", "enabled": true, "limit": 20, "page": 1})
}

fn ihome_detail_read() -> Value {
    json!({"operation": "detail", "enabled": true, "id": 41})
}

/// Run one iHome session flow against the loopback stand-in with an isolated
/// governor. The flag records whether the network factory was consulted.
fn run_ihome_session(
    harness: &CasHarness,
    input: &str,
    name: &str,
) -> (Result<Value, Error>, bool) {
    let (guard, governor) = service_test_governor(name);
    let client = harness.client.clone();
    let mut factory_used = false;
    let result = crate::ihome::session_with_network(input, true, || {
        factory_used = true;
        Ok((client, governor))
    });
    drop(guard);
    (result, factory_used)
}

/// Serve the reviewed CAS callback and the one business read it authorizes.
/// Every callback GET answers with a 302 to `terminal`; the business routes
/// answer with the reviewed JSON body.
fn ihome_responder(
    terminal: &'static str,
    read: impl Into<String> + Send + 'static,
) -> impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static {
    let read = read.into();
    move |request| {
        let path = request.target.split('?').next().unwrap_or("");
        if path == "/api/authLogin" {
            return http_response("302 Found", &[("Location", terminal)], "");
        }
        if path == "/api/appeal" || path.starts_with("/api/appeal/") {
            return http_response("200 OK", &[("Content-Type", "application/json")], &read);
        }
        http_response(
            "404 Not Found",
            &[("Content-Type", "text/plain")],
            "unexpected",
        )
    }
}

/// No observed platform request may ever target the terminal web prefix:
/// the fragment token is consumed in memory, never fetched.
fn assert_terminal_never_fetched(harness: &CasHarness) {
    for request in harness.ihome.observed() {
        assert!(
            !request.target.starts_with("/web/"),
            "the terminal URL must never be requested: {}",
            request.target
        );
    }
}

#[test]
fn ihome_session_list_consumes_the_fragment_token_and_projects_the_listing() {
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
    );
    let (result, factory_used) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-session-list",
    );
    assert!(
        factory_used,
        "an online session consults the network factory"
    );
    let output = result.expect("ihome session result");
    assert_eq!(output["schema_version"], 1);
    assert_eq!(output["type"], "ihome_appeal_list");
    assert_eq!(output["result"], "entries");
    assert_eq!(output["credential_source"], "redirect_fragment_token");
    assert_eq!(output["entry_count"], 1);
    let entries = output["entries"].as_array().expect("projected entries");
    assert_eq!(entries[0]["id"], 41);
    assert_eq!(entries[0]["title"], "synthetic appeal title");
    assert_eq!(entries[0]["content"], "synthetic appeal content");
    assert_eq!(entries[0]["status"], "synthetic-status");
    assert_eq!(entries[0]["reply_count"], 1);
    assert_eq!(
        entries[0]["replies"][0]["department"]["name"],
        "Synthetic Department"
    );
    assert_eq!(entries[0]["departments"][0]["id"], 7);
    assert_eq!(output["next_cursor"]["max_id"], 41);
    assert_eq!(output["next_cursor"]["has_more"], false);
    assert_eq!(output["upstream"]["complete"], true);
    assert_eq!(output["upstream"]["incomplete"], false);
    assert!(output["upstream_evidence"].is_null());
    // No credential material reaches the projection.
    let projected = output.to_string();
    for secret in [
        SESSION_USERNAME,
        SESSION_PASSWORD,
        "CASTGC",
        "host-only-credential",
        IHOME_TOKEN,
    ] {
        assert!(
            !projected.contains(secret),
            "{secret} leaked into the ihome projection"
        );
    }

    // One deliberate sign-on: the form GET and exactly one credential POST,
    // both naming the iHome service declaration.
    assert_one_credential_post(&harness, CasService::Ihome);

    // Exactly one platform callback fetch, performed over HTTPS because the
    // plaintext callback spelling was upgraded, and exactly one business
    // GET under one authentication lease.
    let ihome_requests = harness.ihome.observed();
    assert_eq!(
        ihome_requests.len(),
        2,
        "one callback and one business read"
    );
    let callback = &ihome_requests[0];
    assert_eq!(callback.method, "GET");
    let callback_url = observed_url("i.buaa.edu.cn", callback);
    assert_eq!(callback_url.scheme(), "https");
    assert_eq!(callback_url.path(), "/api/authLogin");
    assert_eq!(
        query_map(&callback_url).get("ticket").map(String::as_str),
        Some("ST-synthetic-ihome")
    );
    let read = &ihome_requests[1];
    assert_eq!(read.method, "GET");
    let target = observed_url("i.buaa.edu.cn", read);
    assert_eq!(target.path(), "/api/appeal");
    assert_eq!(
        query_map(&target).get("limit").map(String::as_str),
        Some("20")
    );
    assert_eq!(
        query_map(&target).get("page").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        read.header("authorization"),
        Some(format!("Bearer {IHOME_TOKEN}").as_str())
    );
    assert_terminal_never_fetched(&harness);
    // Nothing reached the other relying parties.
    assert!(harness.app.observed().is_empty());
    assert!(harness.booking.observed().is_empty());
}

#[test]
fn ihome_session_detail_consumes_the_fragment_token_and_projects_the_appeal() {
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_DETAIL_BODY),
    );
    let (result, factory_used) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_detail_read()),
        "ihome-session-detail",
    );
    assert!(
        factory_used,
        "an online session consults the network factory"
    );
    let output = result.expect("ihome session result");
    assert_eq!(output["type"], "ihome_appeal_detail");
    assert_eq!(output["result"], "appeal");
    assert_eq!(output["credential_source"], "redirect_fragment_token");
    assert_eq!(output["upstream"]["id"], 41);
    let entry = &output["entry"];
    assert_eq!(entry["id"], 41);
    assert_eq!(entry["title"], "synthetic appeal title");
    assert_eq!(entry["content"], "synthetic appeal content");
    assert_eq!(entry["reply_count"], 1);
    assert!(output["upstream_evidence"].is_null());
    let projected = output.to_string();
    for secret in [SESSION_PASSWORD, "host-only-credential", IHOME_TOKEN] {
        assert!(
            !projected.contains(secret),
            "{secret} leaked into the ihome projection"
        );
    }

    assert_one_credential_post(&harness, CasService::Ihome);
    let ihome_requests = harness.ihome.observed();
    assert_eq!(
        ihome_requests.len(),
        2,
        "one callback and one business read"
    );
    let read = &ihome_requests[1];
    assert_eq!(read.method, "GET");
    assert_eq!(observed_url("i.buaa.edu.cn", read).path(), "/api/appeal/41");
    assert_eq!(
        read.header("authorization"),
        Some(format!("Bearer {IHOME_TOKEN}").as_str())
    );
    assert_terminal_never_fetched(&harness);
    assert!(harness.app.observed().is_empty());
    assert!(harness.booking.observed().is_empty());
}

#[test]
fn ihome_session_performs_one_lease_read_without_cache_or_credential_reuse() {
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
    );
    // The first run uses explicit selectors; the second relies on the
    // reviewed defaults and must still authenticate and fetch, proving no
    // response cache, stored session or token reuse short-circuits the
    // one-lease contract.
    let (first, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-session-reuse-first",
    );
    assert_eq!(first.expect("first run")["result"], "entries");
    let (second, _) = run_ihome_session(
        &harness,
        &ihome_session_input(json!({"operation": "list", "enabled": true})),
        "ihome-session-reuse-second",
    );
    let output = second.expect("second run");
    assert_eq!(output["result"], "entries");
    assert_eq!(output["credential_source"], "redirect_fragment_token");

    assert_eq!(
        harness.sso.observed().len(),
        4,
        "two form GETs and two credential POSTs, one sign-on per run"
    );
    assert_eq!(
        harness.ihome.observed().len(),
        4,
        "two callbacks and two business reads, one lease per run"
    );
    assert_terminal_never_fetched(&harness);
}

#[test]
fn ihome_session_terminal_redirect_body_keeps_the_sign_ons_own_classification() {
    // An empty redirect body is the normal terminal answer; a reviewed
    // redirect document is admissible too.
    for (name, body, content_type, expected) in [
        ("empty", "", "text/html", "entries"),
        (
            "clear-redirect-document",
            "<html><body>redirecting</body></html>",
            "text/html",
            "entries",
        ),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    return http_response(
                        "302 Found",
                        &[("Location", IHOME_TERMINAL), ("Content-Type", content_type)],
                        body,
                    );
                }
                if path == "/api/appeal" {
                    return http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        IHOME_LIST_BODY,
                    );
                }
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-terminal-body-{name}"),
        );
        let output = result.expect(name);
        assert_eq!(output["result"], expected, "{name}");
        assert_eq!(
            output["credential_source"], "redirect_fragment_token",
            "{name}"
        );
        assert_eq!(harness.ihome.observed().len(), 2, "{name}");
    }

    // A terminal redirect carrying a challenge form never proves login by
    // token alone: the attempt stops and no business read is sent.
    let challenged = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        move |request| {
            let path = request.target.split('?').next().unwrap_or("");
            if path == "/api/authLogin" {
                return http_response(
                    "302 Found",
                    &[("Location", IHOME_TERMINAL), ("Content-Type", "text/html")],
                    "<html><body><form><label>验证码<input name=\"captcha\"></label></form></body></html>",
                );
            }
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_ihome_session(
        &challenged,
        &ihome_session_input(ihome_list_read()),
        "ihome-terminal-body-challenge",
    );
    assert_eq!(result.unwrap_err().code, "challenge_requires_human");
    assert_one_credential_post(&challenged, CasService::Ihome);
    assert_eq!(
        challenged.ihome.observed().len(),
        1,
        "the challenge stops the flow before the business read"
    );

    // An unreadable nonempty terminal page preserves the source uncertainty
    // instead of accepting the token.
    let unreadable = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        move |request| {
            let path = request.target.split('?').next().unwrap_or("");
            if path == "/api/authLogin" {
                return http_response(
                    "302 Found",
                    &[
                        ("Location", IHOME_TERMINAL),
                        ("Content-Type", "application/xhtml+xml"),
                    ],
                    "<html><body>unreadable</body></html>",
                );
            }
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_ihome_session(
        &unreadable,
        &ihome_session_input(ihome_list_read()),
        "ihome-terminal-body-unreadable",
    );
    assert_eq!(result.unwrap_err().code, "authentication_unconfirmed");
    assert_eq!(unreadable.ihome.observed().len(), 1);
}

#[test]
fn ihome_session_stops_on_a_challenged_or_deferred_sign_on() {
    // A challenge on the platform callback never reaches the business read.
    let challenged = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |request| {
            if request.target.starts_with("/api/authLogin") {
                http_response(
                    "200 OK",
                    &[("Content-Type", "text/html"), ("cf-mitigated", "challenge")],
                    "<html><body>challenge</body></html>",
                )
            } else {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            }
        },
    );
    let (result, _) = run_ihome_session(
        &challenged,
        &ihome_session_input(ihome_list_read()),
        "ihome-callback-challenge",
    );
    assert_eq!(result.unwrap_err().code, "challenge_requires_human");
    assert_one_credential_post(&challenged, CasService::Ihome);
    assert_eq!(
        challenged.ihome.observed().len(),
        1,
        "only the challenged callback was fetched"
    );

    // A deferred credential POST is a durable cooldown: the redirect is
    // never followed and no platform request is made.
    let deferred = CasHarness::with_service_responders(
        sso_responder(
            CasService::Ihome,
            IHOME_CALLBACK_TICKET,
            &[("Retry-After", "60")],
        ),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
    );
    let (result, _) = run_ihome_session(
        &deferred,
        &ihome_session_input(ihome_list_read()),
        "ihome-post-deferred",
    );
    assert_eq!(result.unwrap_err().code, "cooldown");
    assert_one_credential_post(&deferred, CasService::Ihome);
    assert!(
        deferred.ihome.observed().is_empty(),
        "the deferred redirect is never followed"
    );

    // A cooldown on the terminal redirect is respected before the token is
    // accepted: no business read follows it.
    let callback_deferred = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |request| {
            if request.target.starts_with("/api/authLogin") {
                http_response(
                    "302 Found",
                    &[("Location", IHOME_TERMINAL), ("Retry-After", "60")],
                    "",
                )
            } else {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            }
        },
    );
    let (result, _) = run_ihome_session(
        &callback_deferred,
        &ihome_session_input(ihome_list_read()),
        "ihome-terminal-deferred",
    );
    assert_eq!(result.unwrap_err().code, "cooldown");
    assert_eq!(
        callback_deferred.ihome.observed().len(),
        1,
        "the cooldown stops the flow before the business read"
    );
    assert_terminal_never_fetched(&callback_deferred);
}

#[test]
fn ihome_session_refuses_shaped_callbacks_and_plaintext_downgrades() {
    // A credential POST redirected at a shaped or non-reviewed plaintext
    // target is refused before any platform request is made.
    for (name, landing) in [
        (
            "userinfo",
            "http://operator@i.buaa.edu.cn/api/authLogin?ticket=ST-synthetic-ihome",
        ),
        (
            "explicit-port",
            "http://i.buaa.edu.cn:8080/api/authLogin?ticket=ST-synthetic-ihome",
        ),
        (
            "path-widening",
            "http://i.buaa.edu.cn/api/authLogin/extra?ticket=ST-synthetic-ihome",
        ),
        (
            "foreign-host",
            "http://ihome.buaa.edu.cn/api/authLogin?ticket=ST-synthetic-ihome",
        ),
        (
            "foreign-booking",
            "https://booking.lib.buaa.edu.cn/v4/login/cas?cas=ST-synthetic",
        ),
        (
            "https-business-path",
            "https://i.buaa.edu.cn/api/appeal?limit=20&page=1",
        ),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, landing, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-shaped-callback-{name}"),
        );
        assert_eq!(
            result.unwrap_err().code,
            "authentication_unconfirmed",
            "{name}"
        );
        assert_one_credential_post(&harness, CasService::Ihome);
        assert!(
            harness.ihome.observed().is_empty(),
            "{name}: no platform request may follow a refused callback"
        );
        assert!(
            harness.app.observed().is_empty() && harness.booking.observed().is_empty(),
            "{name}: no request may reach another relying party"
        );
    }

    // A plaintext redirect at a non-callback platform path is a downgrade
    // and refuses: the callback itself was fetched over HTTPS, but the
    // follow is never performed.
    let downgrade = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |request| {
            if request.target.starts_with("/api/authLogin") {
                http_response(
                    "302 Found",
                    &[("Location", "http://i.buaa.edu.cn/api/appeal?limit=20")],
                    "",
                )
            } else {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            }
        },
    );
    let (result, _) = run_ihome_session(
        &downgrade,
        &ihome_session_input(ihome_list_read()),
        "ihome-plaintext-downgrade",
    );
    assert_eq!(result.unwrap_err().code, "authentication_unconfirmed");
    assert_eq!(
        downgrade.ihome.observed().len(),
        1,
        "only the HTTPS callback was fetched; the plaintext follow was refused"
    );
}

#[test]
fn ihome_session_refuses_a_malformed_or_nonterminal_terminal_fragment() {
    for (name, terminal) in [
        ("nonterminal-fragment", "http://i.buaa.edu.cn/web/#/login"),
        ("missing-token", "http://i.buaa.edu.cn/web/#/login?type=0"),
        (
            "missing-type",
            "http://i.buaa.edu.cn/web/#/login?token=synthetic-ihome-token",
        ),
        (
            "wrong-type",
            "http://i.buaa.edu.cn/web/#/login?type=1&token=synthetic-ihome-token",
        ),
        (
            "empty-token",
            "http://i.buaa.edu.cn/web/#/login?type=0&token=",
        ),
        (
            "duplicated-token",
            "http://i.buaa.edu.cn/web/#/login?type=0&token=a&token=b",
        ),
        (
            "query-carried-token",
            "http://i.buaa.edu.cn/web/?type=0&token=synthetic-ihome-token",
        ),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            ihome_responder(terminal, IHOME_LIST_BODY),
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-terminal-{name}"),
        );
        assert_eq!(
            result.unwrap_err().code,
            "authentication_unconfirmed",
            "{name}"
        );
        assert_one_credential_post(&harness, CasService::Ihome);
        assert_eq!(
            harness.ihome.observed().len(),
            1,
            "{name}: only the callback may be fetched"
        );
        assert_terminal_never_fetched(&harness);
    }
}

#[test]
fn ihome_session_never_replays_a_credential_preserving_redirect() {
    for status in ["307 Temporary Redirect", "308 Permanent Redirect"] {
        let original = sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]);
        let harness = CasHarness::with_service_responders(
            move |request| {
                if request.method == "POST" {
                    http_response(status, &[("Location", IHOME_CALLBACK_TICKET)], "")
                } else {
                    original(request)
                }
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-post-redirect-{status}"),
        );
        assert!(
            result.is_err(),
            "credential-preserving redirects cannot become a new authentication send"
        );
        assert_eq!(result.unwrap_err().code, "auth_latched");
        assert_one_credential_post(&harness, CasService::Ihome);
        assert!(
            harness.ihome.observed().is_empty(),
            "the method-preserving redirect target is never requested"
        );
    }
}

#[test]
fn ihome_session_degrades_a_listing_that_echoes_credential_material() {
    use base64::Engine as _;
    let encoded_token = base64::engine::general_purpose::STANDARD.encode(IHOME_TOKEN);
    let escaped_token = "synthetic\\u002dihome\\u002dtoken";
    for (name, secret, body) in [
        (
            "terminal-token",
            IHOME_TOKEN,
            IHOME_LIST_BODY.replace("synthetic appeal content", IHOME_TOKEN),
        ),
        (
            "password",
            SESSION_PASSWORD,
            IHOME_LIST_BODY.replace("synthetic appeal content", SESSION_PASSWORD),
        ),
        (
            "username",
            SESSION_USERNAME,
            IHOME_LIST_BODY.replace("synthetic appeal content", SESSION_USERNAME),
        ),
        (
            "current-sign-on-cookie",
            "host-only-credential",
            IHOME_LIST_BODY.replace("synthetic appeal content", "host-only-credential"),
        ),
        (
            "encoded-token",
            encoded_token.as_str(),
            IHOME_LIST_BODY.replace("synthetic appeal content", encoded_token.as_str()),
        ),
        (
            "decoded-token",
            IHOME_TOKEN,
            IHOME_LIST_BODY.replace("synthetic appeal content", escaped_token),
        ),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            ihome_responder(IHOME_TERMINAL, body),
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-echo-{name}"),
        );
        let output = result.expect("an echo degrades gracefully, it does not error");
        assert_eq!(output["type"], "ihome_appeal_list", "{name}");
        assert_eq!(output["result"], "degraded", "{name}");
        assert_eq!(output["entry_count"], 0, "{name}");
        assert!(output["next_cursor"].is_null(), "{name}");
        let evidence = &output["upstream_evidence"];
        assert_eq!(evidence["fallback_reason"], "credential_echo", "{name}");
        assert_eq!(
            evidence["evidence_kind"], "upstream_http_metadata",
            "{name}"
        );
        assert_eq!(evidence["http_status"], 200, "{name}");
        assert!(
            !output.to_string().contains(secret),
            "{name}: the echoed credential was released"
        );
        // The business read happened exactly once and settled; the flow did
        // not retry after the echo.
        assert_eq!(harness.ihome.observed().len(), 2, "{name}");
        assert_terminal_never_fetched(&harness);
    }
}

#[test]
fn ihome_session_degrades_a_numeric_token_echo() {
    // A token spelling the platform could return as a JSON number is still
    // the credential: the numeric projection of the body is screened.
    let terminal = "http://i.buaa.edu.cn/web/#/login?type=0&token=7008133700";
    let body = r#"{"code":20000,"success":true,"data":{"current_page":1,"last_page":1,"total":7008133700,"data":[]}}"#;
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(terminal, body),
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-numeric-echo",
    );
    let output = result.expect("a numeric echo degrades gracefully");
    assert_eq!(output["result"], "degraded");
    assert_eq!(
        output["upstream_evidence"]["fallback_reason"],
        "credential_echo"
    );
    assert!(!output.to_string().contains("7008133700"));
}

#[test]
fn ihome_session_degrades_a_detail_that_echoes_a_retired_cookie_value() {
    // The callback replaces its platform session cookie; the replaced value
    // stays inside the attempt's privacy guard and an echo of it is
    // withheld like any live credential.
    let body = IHOME_DETAIL_BODY.replace("synthetic appeal content", "retired-private-alpha");
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        move |request| {
            let path = request.target.split('?').next().unwrap_or("");
            if path == "/api/authLogin" {
                return http_response(
                    "302 Found",
                    &[
                        ("Location", IHOME_TERMINAL),
                        (
                            "Set-Cookie",
                            "ihome_sid=retired-private-alpha; Path=/; Secure; HttpOnly",
                        ),
                        (
                            "Set-Cookie",
                            "ihome_sid=retired-private-beta; Path=/; Secure; HttpOnly",
                        ),
                    ],
                    "",
                );
            }
            if path.starts_with("/api/appeal/") {
                return http_response("200 OK", &[("Content-Type", "application/json")], &body);
            }
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_detail_read()),
        "ihome-retired-cookie-echo",
    );
    let output = result.expect("a retired-cookie echo degrades gracefully");
    assert_eq!(output["type"], "ihome_appeal_detail");
    assert_eq!(output["result"], "degraded");
    assert!(output["entry"].is_null());
    assert_eq!(
        output["upstream_evidence"]["fallback_reason"],
        "credential_echo"
    );
    assert!(
        !output.to_string().contains("retired-private-alpha"),
        "the echoed retired cookie value was released"
    );
    assert_eq!(harness.ihome.observed().len(), 2);
}

#[test]
fn ihome_session_degrades_a_mime_echo_without_leaking_the_content_type() {
    use sha2::Digest as _;
    // A token echoed inside the retained content type header is a
    // credential echo: the body is never projected, the MIME value is
    // nulled and its parameters are withheld, and the degrading evidence
    // keeps only the safe status, length and hash facts.
    for secret in [IHOME_TOKEN, SESSION_PASSWORD, "host-only-credential"] {
        let body = IHOME_LIST_BODY;
        let mime = format!("application/json; profile=\"{secret}\"");
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
                }
                if path == "/api/appeal" {
                    return http_response("200 OK", &[("Content-Type", mime.as_str())], body);
                }
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            "ihome-mime-echo",
        );
        let output = result.expect("a MIME echo degrades gracefully");
        assert_eq!(output["result"], "degraded");
        let evidence = &output["upstream_evidence"];
        assert_eq!(evidence["fallback_reason"], "credential_echo");
        assert!(evidence["content_type"].is_null());
        assert_eq!(evidence["content_type_parameters_withheld"], true);
        assert_eq!(evidence["http_status"], 200);
        assert_eq!(evidence["byte_length"], body.len());
        let digest = format!("{:x}", sha2::Sha256::digest(body.as_bytes()));
        assert_eq!(evidence["sha256"], digest);
        assert!(!output.to_string().contains(secret));
        assert_eq!(harness.ihome.observed().len(), 2);
    }
}

// ---------------------------------------------------------------------------
// Review regressions: a business read may itself issue cookies. Those newly
// issued values are session material even though they were never transmitted
// or adopted, so an echo of one inside the response is a credential echo.
// The values are reviewed from the raw header map: the retained-header
// projection never carries Set-Cookie, so a post-collection guard cannot
// see them.
// ---------------------------------------------------------------------------

#[test]
fn ihome_session_degrades_a_read_that_echoes_a_newly_issued_cookie_value() {
    use base64::Engine as _;
    // Every spelling a consumer could observe is withheld: an ordinary
    // listing field, a JSON-escaped fallback and the emitted MIME metadata.
    for (name, cookies, content_type, body) in [
        (
            "short",
            vec!["ihome_read=x9k2; Path=/; Secure; HttpOnly"],
            "application/json",
            IHOME_LIST_BODY.replace("synthetic appeal content", "x9k2"),
        ),
        (
            "path-scoped",
            vec!["ihome_read=scoped-private-value; Path=/api; Secure"],
            "application/json",
            IHOME_LIST_BODY.replace("synthetic appeal content", "scoped-private-value"),
        ),
        (
            "superseded",
            vec![
                "ihome_read=first-private-value; Path=/; Secure",
                "ihome_read=second-private-value; Path=/; Secure",
            ],
            "application/json",
            IHOME_LIST_BODY.replace("synthetic appeal content", "first-private-value"),
        ),
        (
            "base64",
            vec!["ihome_read=b64-issued-secret; Path=/; Secure"],
            "application/json",
            IHOME_LIST_BODY.replace(
                "synthetic appeal content",
                base64::engine::general_purpose::STANDARD
                    .encode("b64-issued-secret")
                    .as_str(),
            ),
        ),
        (
            "json-escaped",
            vec!["ihome_read=esc-issued-secret; Path=/; Secure"],
            "application/json",
            IHOME_LIST_BODY.replace("synthetic appeal content", "esc\\u002dissued\\u002dsecret"),
        ),
        (
            "mime",
            vec!["ihome_read=mime-issued-secret; Path=/; Secure"],
            "application/json; profile=\"mime-issued-secret\"",
            IHOME_LIST_BODY.to_string(),
        ),
    ] {
        let served = cookies.clone();
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
                }
                if path == "/api/appeal" {
                    let mut headers = vec![("Content-Type", content_type)];
                    for cookie in &served {
                        headers.push(("Set-Cookie", *cookie));
                    }
                    return http_response("200 OK", &headers, &body);
                }
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-issued-cookie-{name}"),
        );
        let output = result.expect("a newly issued cookie echo degrades gracefully");
        assert_eq!(output["type"], "ihome_appeal_list", "{name}");
        assert_eq!(output["result"], "degraded", "{name}");
        assert_eq!(output["entry_count"], 0, "{name}");
        let evidence = &output["upstream_evidence"];
        assert_eq!(evidence["fallback_reason"], "credential_echo", "{name}");
        assert_eq!(
            evidence["evidence_kind"], "upstream_http_metadata",
            "{name}"
        );
        if name == "mime" {
            // The MIME echo is nulled in both the page metadata and the
            // evidence; a withheld body never emits raw bytes.
            assert!(evidence["content_type"].is_null(), "{name}");
            assert_eq!(evidence["content_type_parameters_withheld"], true, "{name}");
            assert!(
                output["upstream"]["pages"][0]["content_type"].is_null(),
                "{name}"
            );
        } else {
            assert_eq!(evidence["content_type"], "application/json", "{name}");
        }
        assert!(
            evidence.get("raw_response_base64").is_none(),
            "{name}: a withheld body never emits raw bytes"
        );
        for cookie in &cookies {
            let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
            assert!(
                !output.to_string().contains(value),
                "{name}: the issued cookie value {value} was released"
            );
        }
        // The issued cookie is never transmitted back: the read is the
        // last request of the attempt and carries no Cookie header.
        let observed = harness.ihome.observed();
        let read = &observed[1];
        assert!(
            read.header("cookie").is_none(),
            "{name}: the issued cookie must never be transmitted"
        );
        assert_eq!(observed.len(), 2, "{name}");
        assert_terminal_never_fetched(&harness);
    }
}

#[test]
fn ihome_session_projects_a_cookie_issuing_read_without_echo() {
    // Issuance alone is not a refusal: an ordinary body is still projected.
    // The response is session material, so the issued value never reaches
    // the output, the read never sends a Cookie header and nothing is
    // retained for replay.
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |request| {
            let path = request.target.split('?').next().unwrap_or("");
            if path == "/api/authLogin" {
                return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
            }
            if path == "/api/appeal" {
                return http_response(
                    "200 OK",
                    &[
                        ("Content-Type", "application/json"),
                        (
                            "Set-Cookie",
                            "ihome_read=issued-ordinary-private; Path=/; Secure; HttpOnly",
                        ),
                    ],
                    IHOME_LIST_BODY,
                );
            }
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-issued-cookie-ordinary",
    );
    let output = result.expect("an ordinary cookie-issuing read is admissible");
    assert_eq!(output["result"], "entries");
    assert_eq!(output["entry_count"], 1);
    // The read really fetched the response: it was not replayed from any
    // cache, and a cookie-issuing response is never retained for replay.
    assert_eq!(output["provenance"]["cache_status"], "miss");
    let projected = output.to_string();
    assert!(
        !projected.contains("issued-ordinary-private"),
        "the issued cookie value reached the projection"
    );
    // The one network read cannot have been replayed from a cache.
    let observed = harness.ihome.observed();
    assert_eq!(observed.len(), 2, "one callback and one business read");
    assert!(
        observed[1].header("cookie").is_none(),
        "an issued cookie is never transmitted"
    );
    assert_terminal_never_fetched(&harness);
}

#[test]
fn ihome_session_refuses_an_unreviewable_set_cookie_header() {
    // A Set-Cookie that cannot be parsed on its own terms cannot be
    // screened, so the response is refused instead of projecting a body
    // that might carry the unreviewable secret. The request already
    // settled: the refusal is admission, never a retry.
    for (name, header) in [
        ("missing-equals", "no-equals-sign"),
        ("empty-name", "=orphaned-value; Path=/"),
        ("unbalanced-quote", "ihome_read=\"unbalanced; Path=/"),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
                }
                if path == "/api/appeal" {
                    return http_response(
                        "200 OK",
                        &[("Content-Type", "application/json"), ("Set-Cookie", header)],
                        IHOME_LIST_BODY,
                    );
                }
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-set-cookie-unreviewable-{name}"),
        );
        let error = result.expect_err("an unreviewable Set-Cookie refuses the response");
        assert_eq!(error.code, "invalid_headers", "{name}");
        assert!(!error.message.contains("orphaned-value"), "{name}");
        assert!(!error.message.contains("unbalanced"), "{name}");
        assert_eq!(
            harness.ihome.observed().len(),
            2,
            "{name}: the read happened once; refusal is not a retry"
        );
    }
}

#[test]
fn ihome_cookie_admission_failure_keeps_original_denial_challenge_and_cooldown() {
    for (name, status, mime, body, expected_failures) in [
        (
            "denial",
            "200 OK",
            "application/json",
            r#"{"success":false,"message":"not logged in"}"#,
            2,
        ),
        (
            "challenge",
            "200 OK",
            "text/html",
            "<html><body><form><label>验证码<input name=\"captcha\"></label></form></body></html>",
            2,
        ),
        (
            "http-refusal",
            "403 Forbidden",
            "application/json",
            r#"{"message":"forbidden"}"#,
            2,
        ),
        (
            "ordinary-complete-response",
            "200 OK",
            "application/json",
            r#"{"success":true,"data":{"data":[]}}"#,
            0,
        ),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| http_response("404 Not Found", &[], "unexpected"),
            |_| http_response("404 Not Found", &[], "unexpected"),
            move |request| {
                if request.target.starts_with("/api/authLogin") {
                    return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
                }
                http_response(
                    status,
                    &[
                        ("Content-Type", mime),
                        ("Set-Cookie", "missing-equals"),
                        ("Retry-After", "60"),
                    ],
                    body,
                )
            },
        );
        let (directory, governor) = service_test_governor(&format!("ihome-cookie-lease-{name}"));
        // Seed only this newly owned fixture's valid prior network history.
        // A confirmed refusal/challenge must not settle as a successful 200;
        // ordinary complete responses must still clear that failure streak.
        let state_path = directory.path.join("state.json");
        let mut initial: Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        initial["network_failures"] = json!(2);
        std::fs::write(&state_path, serde_json::to_vec(&initial).unwrap()).unwrap();
        let client = harness.client.clone();
        let error = crate::ihome::session_with_network(
            &ihome_session_input(ihome_list_read()),
            true,
            || Ok((client, governor)),
        )
        .expect_err("unreviewable cookie admission refuses projection");
        assert_eq!(error.code, "invalid_headers", "{name}");
        let governor = Governor::isolated_for_test(&directory.path).unwrap();
        let state = governor.status().unwrap();
        assert_eq!(
            state.consecutive_network_failures, expected_failures,
            "{name}: independent original response facts determine success"
        );
        assert!(
            !state.cooldown_wait.is_zero(),
            "{name}: the original Retry-After stays durable"
        );
        assert_eq!(harness.ihome.observed().len(), 2, "{name}: no retry");
        assert_terminal_never_fetched(&harness);
    }
}

#[test]
fn ihome_list_keeps_issued_cookie_guard_across_fresh_and_cached_pages() {
    const ISSUED: &str = "issued-earlier-page-private";
    for (name, cached, echo) in [
        ("fresh-body", false, "body"),
        ("cached-body", true, "body"),
        ("fresh-mime", false, "mime"),
        ("cached-mime", true, "mime"),
        ("ordinary", false, "none"),
    ] {
        let mut first: Value = serde_json::from_str(IHOME_LIST_BODY).unwrap();
        first["data"]["last_page"] = json!(2);
        first["data"]["total"] = json!(2);
        let mut second = first.clone();
        second["data"]["current_page"] = json!(2);
        second["data"]["data"][0]["id"] = json!(42);
        if echo == "body" {
            second["data"]["data"][0]["content"] = json!(ISSUED);
        }
        let first_body = first.to_string();
        let second_body = second.to_string();
        let second_mime = if echo == "mime" {
            format!("application/json; profile=\"{ISSUED}\"")
        } else {
            "application/json".to_string()
        };
        let harness = CasHarness::with_service_responders(
            |_| http_response("404 Not Found", &[], "unexpected"),
            |_| http_response("404 Not Found", &[], "unexpected"),
            |_| http_response("404 Not Found", &[], "unexpected"),
            move |request| {
                let target = observed_url("i.buaa.edu.cn", request);
                if target.path() == "/api/appeal" {
                    let query = query_map(&target);
                    match query.get("page").map(String::as_str) {
                        Some("1") => {
                            return http_response(
                                "200 OK",
                                &[
                                    ("Content-Type", "application/json"),
                                    (
                                        "Set-Cookie",
                                        "sid=issued-earlier-page-private; Path=/api; Secure; HttpOnly",
                                    ),
                                ],
                                &first_body,
                            );
                        }
                        Some("2") => {
                            return http_response(
                                "200 OK",
                                &[("Content-Type", second_mime.as_str())],
                                &second_body,
                            );
                        }
                        _ => {}
                    }
                }
                http_response("404 Not Found", &[], "unexpected")
            },
        );
        let (directory, governor) = service_test_governor(&format!("ihome-pages-{name}"));
        let cache_directory = directory.path.join("response-cache");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&cache_directory)
            .unwrap();
        let governor = if cached {
            // A previous invocation saw this page as ordinary data, before
            // any response had issued ISSUED as a credential. Its native
            // successful read supplies the real cache entry for page two.
            let baseline = crate::ihome::list_with_test_network(
                &json!({"token":IHOME_TOKEN,"limit":1,"page":2,"max_pages":1}).to_string(),
                &cache_directory,
                harness.client.clone(),
                governor,
            )
            .expect("the earlier invocation admits ordinary data");
            assert_eq!(baseline["result"], "entries", "{name}");
            assert_eq!(baseline["entry_count"], 1, "{name}");
            Governor::isolated_for_test(&directory.path.join("next-invocation")).unwrap()
        } else {
            governor
        };
        // The production lazy collector holds one guard over page one and
        // page two. Only page one issues a cookie; page two must be screened
        // with that retained value whether fetched or replayed from cache.
        let output = crate::ihome::list_with_test_network(
            &json!({"token":IHOME_TOKEN,"limit":1,"page":1,"max_pages":2}).to_string(),
            &cache_directory,
            harness.client.clone(),
            governor,
        )
        .expect("the bounded traversal settles normally");
        if echo == "none" {
            assert_eq!(output["result"], "entries", "{name}");
            assert_eq!(output["entry_count"], 2, "{name}");
            assert_eq!(output["upstream"]["complete"], true, "{name}");
            // The cookie-issuing first response is never cached; only the
            // ordinary, non-issuing second response may remain.
            assert_eq!(
                std::fs::read_dir(&cache_directory).unwrap().count(),
                1,
                "{name}"
            );
        } else {
            assert_eq!(output["result"], "degraded", "{name}");
            assert_eq!(
                output["entry_count"], 1,
                "{name}: retain only the safe first page"
            );
            assert!(output["next_cursor"].is_null(), "{name}");
            let evidence = &output["upstream_evidence"];
            assert_eq!(evidence["fallback_reason"], "credential_echo", "{name}");
            assert!(evidence.get("raw_response_base64").is_none(), "{name}");
            if echo == "mime" {
                assert!(evidence["content_type"].is_null(), "{name}");
                assert!(
                    output["upstream"]["pages"][1]["content_type"].is_null(),
                    "{name}"
                );
                assert_eq!(evidence["content_type_parameters_withheld"], true, "{name}");
            }
            // Neither the issuing response nor a later echoed response is
            // cached. An existing echoed cache entry is removed too.
            assert_eq!(
                std::fs::read_dir(&cache_directory).unwrap().count(),
                0,
                "{name}"
            );
        }
        assert!(!output.to_string().contains(ISSUED), "{name}");
        assert_eq!(
            output["upstream"]["pages"].as_array().unwrap().len(),
            2,
            "{name}"
        );
        let observed = harness.ihome.observed();
        assert_eq!(
            observed.len(),
            2,
            "{name}: no retries or speculative page fetches"
        );
        let observed_pages = observed
            .iter()
            .map(|request| {
                assert!(
                    request.header("cookie").is_none(),
                    "{name}: no cookie adoption/transmission"
                );
                assert_eq!(
                    request.header("authorization"),
                    Some(format!("Bearer {IHOME_TOKEN}").as_str())
                );
                query_map(&observed_url("i.buaa.edu.cn", request))["page"].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed_pages,
            if cached { ["2", "1"] } else { ["1", "2"] },
            "{name}"
        );
        assert!(
            harness.sso.observed().is_empty(),
            "legacy reads do not authenticate"
        );
        assert!(harness.app.observed().is_empty());
        assert!(harness.booking.observed().is_empty());
    }
}

#[test]
fn ihome_session_withholds_nested_fallback_cookie_echoes_but_keeps_ordinary_fallback() {
    use base64::Engine as _;
    for (name, inner, echoed, unreviewed) in [
        (
            "issued",
            r#"{"note":"nested-issued-secr\u0065t"}"#.to_string(),
            true,
            false,
        ),
        (
            "ordinary",
            r#"{"note":"ordinary"}"#.to_string(),
            false,
            false,
        ),
        (
            "container-limit",
            format!(
                "{}{}{}",
                "[".repeat(129),
                r#""nested-issued-secr\u0065t""#,
                "]".repeat(129)
            ),
            false,
            true,
        ),
        (
            "ordinary-at-container-boundary",
            format!("{}{}{}", "[".repeat(127), r#""ordinary""#, "]".repeat(127)),
            false,
            false,
        ),
        (
            "echo-at-container-boundary",
            format!(
                "{}{}{}",
                "[".repeat(127),
                r#""nested-issued-secr\u0065t""#,
                "]".repeat(127)
            ),
            true,
            false,
        ),
    ] {
        // The full text/plain body is not JSON. Its recovered string literal
        // decodes to an embedded document whose own escaped value requires
        // the same bounded recursion as the primary JSON inspection.
        let body = format!("prefix {} suffix", serde_json::to_string(&inner).unwrap());
        let served = body.clone();
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| http_response("404 Not Found", &[], "unexpected"),
            |_| http_response("404 Not Found", &[], "unexpected"),
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
                }
                if path == "/api/appeal" {
                    return http_response(
                        "200 OK",
                        &[
                            ("Content-Type", "text/plain"),
                            (
                                "Set-Cookie",
                                "ihome_read=nested-issued-secret; Path=/; Secure; HttpOnly",
                            ),
                        ],
                        &served,
                    );
                }
                http_response("404 Not Found", &[], "unexpected")
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-nested-fallback-{name}"),
        );
        if unreviewed {
            // The native read must refuse admission on inspection exhaustion,
            // not turn a decoder-limit error into a raw-fallback success.
            let error = result.expect_err("container exhaustion withholds the response");
            assert_eq!(error.code, "response_unreviewed", "{name}");
            assert!(!error.message.contains("nested-issued-secret"), "{name}");
            assert!(
                !error.message.contains(
                    base64::engine::general_purpose::STANDARD
                        .encode(body.as_bytes())
                        .as_str()
                ),
                "{name}"
            );
            assert_eq!(harness.ihome.observed().len(), 2, "{name}: no retry");
            assert_terminal_never_fetched(&harness);
            continue;
        }
        let output = result.expect("one read settles without retry");
        assert_eq!(output["result"], "degraded", "{name}");
        let evidence = &output["upstream_evidence"];
        if echoed {
            assert_eq!(evidence["fallback_reason"], "credential_echo", "{name}");
            assert_eq!(
                evidence["evidence_kind"], "upstream_http_metadata",
                "{name}"
            );
            assert!(evidence.get("raw_response_base64").is_none(), "{name}");
            assert!(
                !output.to_string().contains("nested-issued-secret"),
                "{name}"
            );
            assert!(
                !output.to_string().contains(
                    base64::engine::general_purpose::STANDARD
                        .encode(body.as_bytes())
                        .as_str()
                ),
                "{name}"
            );
        } else {
            assert_eq!(evidence["fallback_reason"], "unexpected_content", "{name}");
            assert_eq!(
                evidence["raw_response_base64"],
                base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
                "{name}"
            );
        }
        assert_eq!(harness.ihome.observed().len(), 2, "{name}");
        assert_terminal_never_fetched(&harness);
    }
}

// ---------------------------------------------------------------------------
// Review regressions: the complete transmitted Cookie header is itself a
// credential. Its base64 spelling carries neither the cookie names nor the
// individual cookie values that are screened on their own, so a response
// that reflects the whole header must still be withheld.
// ---------------------------------------------------------------------------

/// The exact `Cookie` header one iHome attempt really transmits. The value
/// is read from an observed request of a completed attempt, so a regression
/// always screens the header that was actually sent instead of an assumed
/// spelling.
fn ihome_review_regression_transmitted_cookie_header(name: &str) -> String {
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
    );
    let (result, _) = run_ihome_session(&harness, &ihome_session_input(ihome_list_read()), name);
    let output = result.expect("the ordinary listing is admissible");
    assert_eq!(
        output["result"], "entries",
        "the probe attempt must authenticate and project its listing"
    );
    let headers = ihome_review_regression_transmitted_cookie_headers(&harness);
    assert!(
        !headers.is_empty(),
        "the sign-on exchange transmits a Cookie header"
    );
    headers
        .into_iter()
        .next()
        .expect("a transmitted Cookie header")
}

/// Every `Cookie` header one attempt really transmitted, in request order.
/// An empty header is not a header.
fn ihome_review_regression_transmitted_cookie_headers(harness: &CasHarness) -> Vec<String> {
    let sign_on = harness.sso.observed();
    let platform = harness.ihome.observed();
    sign_on
        .iter()
        .chain(platform.iter())
        .filter_map(|request| request.header("cookie"))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

/// The encoded complete header must stay outside every spelling that is
/// already screened on its own: it carries no cookie value, no username or
/// password and no standalone reversible spelling of one. Only the complete
/// transmitted header identifies it.
fn ihome_review_regression_assert_uniquely_identified(encoded: &str) {
    use base64::Engine as _;
    for guarded in [
        "host-only-credential",
        SESSION_USERNAME,
        SESSION_PASSWORD,
        IHOME_TOKEN,
    ] {
        assert!(
            !encoded.contains(guarded),
            "{guarded} is spelled inside the encoded header"
        );
        for spelling in [
            base64::engine::general_purpose::STANDARD.encode(guarded),
            base64::engine::general_purpose::URL_SAFE.encode(guarded),
        ] {
            assert!(
                !encoded.contains(spelling.trim_end_matches('=')),
                "{guarded} has a reversible spelling inside the encoded header"
            );
        }
    }
}

/// A listing that reflects the complete transmitted Cookie header in base64
/// is a credential echo. The attempt itself succeeds: the sign-on completes,
/// the platform answers with an otherwise valid listing envelope and only
/// that envelope decides the outcome.
#[test]
fn ihome_review_regression_withholds_a_listing_that_reflects_the_transmitted_cookie_header() {
    use base64::Engine as _;
    let transmitted =
        ihome_review_regression_transmitted_cookie_header("ihome-review-regression-header-probe");
    assert_eq!(
        transmitted, "CASTGC=host-only-credential",
        "the synthetic sign-on transmits the complete name=value header"
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(&transmitted);
    ihome_review_regression_assert_uniquely_identified(&encoded);

    let body = IHOME_LIST_BODY.replace("synthetic appeal content", encoded.as_str());
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, body),
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-review-regression-header-listing",
    );
    // This attempt transmitted the very header the body reflects.
    let observed = ihome_review_regression_transmitted_cookie_headers(&harness);
    assert!(
        observed.iter().any(|header| header == &transmitted),
        "this attempt transmitted the complete header the body reflects"
    );

    let output = result.expect("a credential echo degrades gracefully, it does not error");
    assert_eq!(output["type"], "ihome_appeal_list");
    assert_eq!(output["result"], "degraded");
    assert_eq!(output["entry_count"], 0);
    assert!(output["next_cursor"].is_null());
    let evidence = &output["upstream_evidence"];
    assert_eq!(evidence["fallback_reason"], "credential_echo");
    assert_eq!(evidence["evidence_kind"], "upstream_http_metadata");
    assert_eq!(evidence["http_status"], 200);
    assert!(
        evidence.get("raw_response_base64").is_none(),
        "the withheld body was exported"
    );
    assert!(
        !output.to_string().contains(&encoded),
        "the encoded transmitted header was released"
    );
    // The business read happened exactly once and settled; the flow did not
    // retry after the echo.
    assert_eq!(harness.ihome.observed().len(), 2);
    assert_terminal_never_fetched(&harness);
}

/// The same complete header is a credential in the retained MIME value, and
/// that boundary is distinct from the body: the body itself stays ordinary,
/// so only the header guard can withhold it.
#[test]
fn ihome_review_regression_withholds_a_mime_that_reflects_the_transmitted_cookie_header() {
    use base64::Engine as _;
    let transmitted =
        ihome_review_regression_transmitted_cookie_header("ihome-review-regression-mime-probe");
    let encoded = base64::engine::general_purpose::STANDARD.encode(&transmitted);
    ihome_review_regression_assert_uniquely_identified(&encoded);

    let mime = format!("application/json; profile=\"{encoded}\"");
    let harness = CasHarness::with_service_responders(
        sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        move |request| {
            let path = request.target.split('?').next().unwrap_or("");
            if path == "/api/authLogin" {
                return http_response("302 Found", &[("Location", IHOME_TERMINAL)], "");
            }
            if path == "/api/appeal" {
                return http_response(
                    "200 OK",
                    &[("Content-Type", mime.as_str())],
                    IHOME_LIST_BODY,
                );
            }
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-review-regression-mime",
    );
    let output = result.expect("a MIME echo degrades gracefully");
    assert_eq!(output["type"], "ihome_appeal_list");
    assert_eq!(output["result"], "degraded");
    assert_eq!(output["entry_count"], 0);
    let evidence = &output["upstream_evidence"];
    assert_eq!(evidence["fallback_reason"], "credential_echo");
    assert!(evidence["content_type"].is_null());
    assert_eq!(evidence["content_type_parameters_withheld"], true);
    assert_eq!(evidence["http_status"], 200);
    assert_eq!(evidence["byte_length"], IHOME_LIST_BODY.len());
    assert!(
        evidence.get("raw_response_base64").is_none(),
        "the withheld body was exported"
    );
    assert!(
        !output.to_string().contains(&encoded),
        "the encoded transmitted header was released"
    );
    assert_eq!(harness.ihome.observed().len(), 2);
    assert_terminal_never_fetched(&harness);
}

const IHOME_CHALLENGE_REVIEW_BODY: &str =
    "<html><body><form><label>验证码<input name=\"captcha\"></label></form></body></html>";

#[test]
fn ihome_challenge_review_regression_redirect_body_challenge_stops_before_the_callback() {
    let harness = CasHarness::with_service_responders(
        |request| {
            if request.method == "POST" {
                return http_response(
                    "302 Found",
                    &[
                        ("Location", IHOME_CALLBACK_TICKET),
                        ("Content-Type", "text/html"),
                    ],
                    IHOME_CHALLENGE_REVIEW_BODY,
                );
            }
            http_response(
                "200 OK",
                &[
                    ("Content-Type", "text/html"),
                    (
                        "Set-Cookie",
                        "CASTGC=host-only-credential; Path=/; Secure; HttpOnly",
                    ),
                ],
                &service_login_page(CasService::Ihome),
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-challenge-review-redirect-body",
    );
    assert!(
        result.is_err(),
        "a challenge in the redirect body must stop the attempt before the callback"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.code, "challenge_requires_human",
        "a challenge in the redirect body must stop the attempt"
    );
    assert_one_credential_post(&harness, CasService::Ihome);
    assert!(
        harness.ihome.observed().is_empty(),
        "the challenged redirect body must stop the flow before the callback"
    );
    assert!(harness.app.observed().is_empty());
    assert!(harness.booking.observed().is_empty());
    for secret in [SESSION_USERNAME, SESSION_PASSWORD, IHOME_TOKEN] {
        assert!(
            !error.message.contains(secret),
            "{secret} leaked into the refusal"
        );
    }
}

#[test]
fn ihome_challenge_review_regression_initial_get_redirect_body_challenge_stops_the_chain() {
    let harness = CasHarness::with_service_responders(
        |request| {
            if request.target.contains("step=challenged") {
                return http_response(
                    "200 OK",
                    &[
                        ("Content-Type", "text/html"),
                        (
                            "Set-Cookie",
                            "CASTGC=host-only-credential; Path=/; Secure; HttpOnly",
                        ),
                    ],
                    &service_login_page(CasService::Ihome),
                );
            }
            http_response(
                "302 Found",
                &[
                    ("Location", "https://sso.buaa.edu.cn/login?step=challenged"),
                    ("Content-Type", "text/html"),
                ],
                IHOME_CHALLENGE_REVIEW_BODY,
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        |_| {
            http_response(
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                "unexpected",
            )
        },
        ihome_responder(IHOME_TERMINAL, IHOME_LIST_BODY),
    );
    let (result, _) = run_ihome_session(
        &harness,
        &ihome_session_input(ihome_list_read()),
        "ihome-challenge-review-initial-get",
    );
    assert!(
        result.is_err(),
        "a challenge in a redirect body must stop the chain"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.code, "challenge_requires_human",
        "a challenge in a redirect body must stop the chain"
    );
    let sign_on = harness.sso.observed();
    assert_eq!(
        sign_on.len(),
        1,
        "only the challenged first hop was sent, the redirect was never followed"
    );
    assert_eq!(sign_on[0].method, "GET");
    assert!(
        harness.ihome.observed().is_empty(),
        "no callback and no business read may follow a challenged redirect"
    );
    assert!(harness.app.observed().is_empty());
    assert!(harness.booking.observed().is_empty());
}

#[test]
fn ihome_challenge_review_regression_cue_controls_refuse_without_rejecting_unrelated_quirks() {
    for (name, body, review_required) in [
        (
            "otp",
            r#"<form><input name="otp" autocomplete="one-time-code" required></form>"#,
            true,
        ),
        (
            "otp-after-quirk",
            r#"<form><input name="username" type="checkbox"><input name="password" type="password"><input name="otp" autocomplete="one-time-code" required></form>"#,
            true,
        ),
        (
            "unrelated-quirk",
            r#"<form><input name="username" type="checkbox"><input name="password" type="password"></form>"#,
            false,
        ),
    ] {
        for &stage in if review_required {
            &[0, 1, 2][..]
        } else {
            &[1, 2][..]
        } {
            let ordinary_sso = sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]);
            let harness = CasHarness::with_service_responders(
                move |request| {
                    if (stage == 0
                        && request.method == "GET"
                        && !request.target.contains("step=next"))
                        || (stage == 1 && request.method == "POST")
                    {
                        let location = if stage == 0 {
                            "https://sso.buaa.edu.cn/login?step=next"
                        } else {
                            IHOME_CALLBACK_TICKET
                        };
                        return http_response(
                            "302 Found",
                            &[("Location", location), ("Content-Type", "text/html")],
                            body,
                        );
                    }
                    ordinary_sso(request)
                },
                |_| {
                    http_response(
                        "404 Not Found",
                        &[("Content-Type", "text/plain")],
                        "unexpected",
                    )
                },
                |_| {
                    http_response(
                        "404 Not Found",
                        &[("Content-Type", "text/plain")],
                        "unexpected",
                    )
                },
                move |request| match request.target.split('?').next().unwrap_or("") {
                    "/api/authLogin" => http_response(
                        "302 Found",
                        &[("Location", IHOME_TERMINAL), ("Content-Type", "text/html")],
                        if stage == 2 { body } else { "" },
                    ),
                    "/api/appeal" => http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        IHOME_LIST_BODY,
                    ),
                    _ => http_response(
                        "404 Not Found",
                        &[("Content-Type", "text/plain")],
                        "unexpected",
                    ),
                },
            );
            let (result, _) = run_ihome_session(
                &harness,
                &ihome_session_input(ihome_list_read()),
                &format!("ihome-review-cue-{name}-{stage}"),
            );
            if review_required {
                let error =
                    result.expect_err("an unreviewed verification control must stop the flow");
                assert_eq!(error.code, "authentication_unconfirmed", "{name}/{stage}");
                assert_eq!(
                    harness.ihome.observed().len(),
                    usize::from(stage == 2),
                    "{name}/{stage}"
                );
                for secret in [SESSION_USERNAME, SESSION_PASSWORD, IHOME_TOKEN] {
                    assert!(
                        !error.message.contains(secret),
                        "{name}/{stage}: credential export"
                    );
                }
            } else {
                let output = result.expect("unrelated control quirks must not become challenges");
                assert_eq!(output["result"], "entries", "{name}/{stage}");
                assert_eq!(harness.ihome.observed().len(), 2, "{name}/{stage}");
            }
            if review_required && stage == 0 {
                assert_eq!(harness.sso.observed().len(), 1, "{name}/{stage}");
            } else {
                assert_one_credential_post(&harness, CasService::Ihome);
            }
            assert_terminal_never_fetched(&harness);
            assert!(harness.app.observed().is_empty());
            assert!(harness.booking.observed().is_empty());
        }
    }
}

#[test]
fn ihome_challenge_review_regression_unreviewed_terminal_mime_refuses_without_a_business_read() {
    for (name, content_type, body) in [
        ("absent-mime", None, IHOME_CHALLENGE_REVIEW_BODY),
        (
            "malformed-mime",
            Some("text/html/../x"),
            IHOME_CHALLENGE_REVIEW_BODY,
        ),
        (
            "unknown-mime",
            Some("application/x-unknown-review-type"),
            IHOME_CHALLENGE_REVIEW_BODY,
        ),
        (
            "html-under-plain-text-mime",
            Some("text/plain"),
            IHOME_CHALLENGE_REVIEW_BODY,
        ),
        ("nbsp-missing-mime", None, "\u{a0}"),
        (
            "em-space-unknown-mime",
            Some("application/x-unknown-review-type"),
            "\u{2003}",
        ),
        (
            "unicode-malformed-mime",
            Some("text/html/../x"),
            " \u{a0}\t",
        ),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    let mut headers: Vec<(&str, &str)> = vec![("Location", IHOME_TERMINAL)];
                    if let Some(mime) = content_type {
                        headers.push(("Content-Type", mime));
                    }
                    return http_response("302 Found", &headers, body);
                }
                if path == "/api/appeal" {
                    return http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        IHOME_LIST_BODY,
                    );
                }
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-challenge-review-mime-{name}"),
        );
        assert!(
            result.is_err(),
            "{name}: an unreviewed terminal MIME must not be promoted to a clear landing"
        );
        let error = result.unwrap_err();
        assert_eq!(
            error.code, "authentication_unconfirmed",
            "{name}: an unreviewed terminal MIME must refuse the token as uncertainty"
        );
        let platform = harness.ihome.observed();
        assert_eq!(platform.len(), 1, "{name}: no business read may follow");
        assert_eq!(platform[0].method, "GET");
        assert_terminal_never_fetched(&harness);
        assert!(harness.app.observed().is_empty(), "{name}");
        assert!(harness.booking.observed().is_empty(), "{name}");
        for secret in [SESSION_USERNAME, SESSION_PASSWORD, IHOME_TOKEN] {
            assert!(
                !error.message.contains(secret),
                "{name}: {secret} leaked into the refusal"
            );
        }
    }
}

#[test]
fn ihome_challenge_review_regression_empty_or_whitespace_terminal_body_stays_admissible() {
    for (name, body, content_type) in [
        (
            "empty-unknown-mime",
            "",
            Some("application/x-unknown-review-type"),
        ),
        ("whitespace-missing-mime", " \t\r\n\x0c", None),
        (
            "whitespace-malformed-mime",
            " \t\r\n",
            Some("text/html/../x"),
        ),
        ("non-ascii-reviewed-html", "\u{a0}", Some("text/html")),
    ] {
        let harness = CasHarness::with_service_responders(
            sso_responder(CasService::Ihome, IHOME_CALLBACK_TICKET, &[]),
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            |_| {
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
            move |request| {
                let path = request.target.split('?').next().unwrap_or("");
                if path == "/api/authLogin" {
                    let mut headers = vec![("Location", IHOME_TERMINAL)];
                    if let Some(mime) = content_type {
                        headers.push(("Content-Type", mime));
                    }
                    return http_response("302 Found", &headers, body);
                }
                if path == "/api/appeal" {
                    return http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        IHOME_LIST_BODY,
                    );
                }
                http_response(
                    "404 Not Found",
                    &[("Content-Type", "text/plain")],
                    "unexpected",
                )
            },
        );
        let (result, _) = run_ihome_session(
            &harness,
            &ihome_session_input(ihome_list_read()),
            &format!("ihome-empty-terminal-{name}"),
        );
        let output = result.expect(name);
        assert_eq!(output["result"], "entries", "{name}");
        assert_eq!(
            output["credential_source"], "redirect_fragment_token",
            "{name}"
        );
        assert_eq!(output["entry_count"], 1, "{name}");
        let platform = harness.ihome.observed();
        assert_eq!(
            platform.len(),
            2,
            "{name}: one callback and one business read"
        );
        assert_terminal_never_fetched(&harness);
    }
}
