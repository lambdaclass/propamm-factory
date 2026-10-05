//! A binary that installed a subscriber of its own before `run_from_env` keeps it: the
//! operator layer's install is a `set_global_default` that yields to one already set. Its
//! own test binary, because a global subscriber is per process.

#[test]
fn a_binarys_own_subscriber_is_kept() {
    use tracing_subscriber::layer::SubscriberExt;
    let own = tracing_subscriber::registry().with(quote_updater::output::layer());
    tracing::subscriber::set_global_default(own).expect("the first install in this process");
    assert!(
        !quote_updater::output::install_for(&["probe"]),
        "a second install changes nothing"
    );
    assert!(!quote_updater::output::install());
}
