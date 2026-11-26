"""PortWatch web interface (read-only for now): History and Results.

Start it from the PortWatch folder:
    streamlit run app.py

Everything it shows comes from the saved scan database. It cannot scan anything,
change a scan, or upgrade the database.

SAFETY RULE for this file: text that comes from scans (target names, banners, notes)
is untrusted. It is displayed only with st.dataframe, st.text, st.code and st.json,
which never interpret it. Never pass scan text to st.markdown, st.write or
unsafe_allow_html, where it could render links, images or HTML.
"""

import streamlit as st

import chain
import storage
import ui_data

PAGES = ["History", "Results"]


def show_history(db):
    st.header("History")
    verification = chain.verify(db)
    level, text = ui_data.verification_message(verification)
    getattr(st, level)(text)

    rows = ui_data.scan_rows(db, verification["scans"])
    if not rows:
        return
    st.dataframe(rows, hide_index=True)
    st.caption("Open the Results page to see the findings of any scan listed here.")
    with st.expander("What do these columns mean?"):
        st.text(
            "Authorization: 'recorded' means the operator confirmed permission before the scan.\n"
            "               'pre-audit' means the scan was saved before that record existed.\n"
            "History:       'verified' means the scan's fingerprint matches its data and links\n"
            "               to the scan before it.\n"
            "               'pre-chain' means it was saved before fingerprints existed.\n"
            "               'BROKEN' means the saved data no longer matches its fingerprint.")


def show_results(db):
    st.header("Results")
    scans = storage.list_scans(db)
    if not scans:
        st.info("No saved scans yet. Run `python run_scan.py` and answer y to save a scan.")
        return

    by_id = {s["id"]: s for s in scans}
    chosen = st.selectbox("Scan", options=list(by_id), format_func=lambda i: ui_data.scan_label(by_id[i]))
    scan = storage.load_scan(db, chosen)
    view = ui_data.scan_view(scan)

    # History status of this scan.
    verification = chain.verify(db)["scans"]
    status = ui_data.history_status(verification, chosen)
    if status == "broken":
        st.error("This scan FAILED history verification: " + "; ".join(verification[chosen]["problems"]))
    elif status == "pre-chain":
        st.info("This scan was saved before fingerprints existed, so it cannot be verified.")
    else:
        st.success("This scan passed history verification.")

    assessment = view["assessment"]
    st.subheader(assessment["verdict"])
    cols = st.columns(5)
    cols[0].metric("Exposure score", assessment["exposure_score"])
    cols[1].metric("Open", view["counts"]["OPEN"])
    cols[2].metric("Closed", view["counts"]["CLOSED"])
    cols[3].metric("No response", view["counts"]["NO_RESPONSE"])
    cols[4].metric("Errors", view["counts"]["ERROR"])

    st.subheader("Findings")
    if view["findings"]:
        st.dataframe(view["findings"], hide_index=True)
    else:
        st.text("No open ports found in this range.")
    if assessment["needs_review"]:
        st.warning("Open ports that could not be identified (not scored): "
                   + ", ".join(str(p) for p in assessment["needs_review"]))
    for note in assessment["coverage_notes"]:
        st.info(note)

    if view["unchecked"]:
        with st.expander(f"Ports without a definite answer ({len(view['unchecked'])})"):
            st.dataframe(view["unchecked"], hide_index=True)

    if view["banners"]:
        with st.expander("Service banners (text sent by the scanned system)"):
            st.caption("Shown exactly as received, after cleaning. Treat it as untrusted.")
            for port, text in view["banners"]:
                st.text(f"Port {port}")
                st.code(text, language=None)

    with st.expander("Scan details"):
        for label, value in view["facts"]:
            st.text(f"{label}: {value}")
        st.json(scan["config"])
        st.text("Fingerprint: " + (scan["fingerprint"] or "none (pre-chain scan)"))

    st.caption(assessment["disclaimer"])


def main():
    st.set_page_config(page_title="PortWatch", layout="wide")
    st.sidebar.title("PortWatch")
    page = st.sidebar.radio("Page", PAGES)

    if ui_data.is_network_exposed(st.get_option("server.address")):
        st.warning("This interface is reachable from other computers on your network, so anyone "
                   "who can reach it can read your scan history. Start it from the PortWatch "
                   "folder with `streamlit run app.py`, or add `--server.address localhost`.")

    path = ui_data.db_path()
    db, problem = ui_data.open_readonly(path)
    st.sidebar.text("Database: " + path)
    st.sidebar.caption("Read-only view.")
    if db is None:
        st.error(problem)
        return
    try:
        if page == "History":
            show_history(db)
        else:
            show_results(db)
    finally:
        db.close()


main()
