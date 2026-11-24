"""DeepHoney Streamlit entry point.

Run with either::

    streamlit run src/deephoney/dashboard/app.py
    python -m deephoney dashboard

The dashboard is an analyst-facing management surface.  The default Compose
deployment binds it to loopback only and places it on the private management
network.  It has no built-in authentication because it is an academic
prototype; do not expose it to an untrusted network.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import streamlit as st

_SRC_ROOT = Path(__file__).resolve().parents[2]
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from deephoney import __version__
from deephoney.dashboard.components import (
    PANEL_CSS,
    empty_state,
    render_error,
    safety_banner,
)
from deephoney.dashboard.data import database_online, get_context
from deephoney.dashboard.pages import (
    cowrie,
    dionaea,
    events,
    overview,
    reports,
    status,
    threat,
)

PageRenderer = Callable[..., None]

PAGES: dict[str, PageRenderer] = {
    "Overview": overview.render,
    "Live / Recent Events": events.render,
    "Cowrie Analysis": cowrie.render,
    "Dionaea Analysis": dionaea.render,
    "Threat Analysis": threat.render,
    "Reports": reports.render,
    "System Status": status.render,
}


def _sidebar(context) -> str:
    with st.sidebar:
        st.markdown(f"## {context.settings.app.name}")
        st.caption("Multi-honeypot monitoring · academic lab build")
        page = st.radio(
            "Navigation",
            options=list(PAGES),
            index=0,
            key="deephoney_page",
        )
        st.divider()
        st.markdown("**Data scope**")
        st.caption(
            "Cowrie and Dionaea are stored as separate source engines. Sessions are "
            "never merged into a single attacker identity."
        )
        st.markdown("**Safety**")
        st.caption(
            "Captured binaries are never served or executed. Passwords are always "
            "redacted in the UI and in exports."
        )
        st.divider()
        st.caption(
            f"Version {__version__} · storage UTC · display {context.settings.app.display_timezone}"
        )
    return page


def _guard_database(context) -> bool:
    try:
        online = database_online(context)
    except Exception as exc:
        render_error(exc)
        return False
    if online:
        return True
    st.error(
        "The PostgreSQL database is not reachable. Start the database, apply migrations "
        "(`alembic upgrade head`), and verify `DATABASE_URL`."
    )
    empty_state(
        "No dashboard data can be loaded yet.",
        "For a local demonstration use `make docker-up` or start PostgreSQL and run "
        "`make migrate` followed by `make seed`.",
    )
    return False


def main() -> None:
    st.set_page_config(
        page_title="DeepHoney",
        page_icon="🍯",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "About": (
                "DeepHoney is a defensive lab project. Risk scores prioritise analyst "
                "review; they are not proof of malicious intent or attribution."
            )
        },
    )
    st.markdown(PANEL_CSS, unsafe_allow_html=True)

    try:
        context = get_context()
    except Exception as exc:
        render_error(exc)
        return

    page = _sidebar(context)
    safety_banner()
    if not _guard_database(context):
        return

    renderer = PAGES.get(page, overview.render)
    try:
        renderer(
            context.repository,
            context.settings,
            timezone_name=context.settings.app.display_timezone,
        )
    except Exception as exc:
        render_error(exc)
        st.caption(
            "If this is the first run, confirm that Alembic migrations are applied and "
            "that the configured database is the one you intended to inspect."
        )
    st.divider()
    st.caption(
        "DeepHoney presents observed honeypot telemetry only. Scores and explanations "
        "are prioritisation aids, not evidence of attribution."
    )


main()
