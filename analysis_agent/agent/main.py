"""Entry point: run the analysis graph in a polling loop."""
import asyncio
import logging
import os
import sys

log = logging.getLogger("analysis_agent")

POLL_INTERVAL_SEC = int(os.environ.get("POLL_INTERVAL_SEC", "300"))


async def _run_loop() -> None:
    from .graph import build_graph
    from .state import SessionAnalysisState

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )

    graph = build_graph()
    log.info(
        "Analysis agent started (poll interval=%ds, model=%s)",
        POLL_INTERVAL_SEC,
        os.environ.get("LLM_MODEL", "gpt-4.1-mini"),
    )

    while True:
        try:
            state = await graph.ainvoke(SessionAnalysisState())
            if state.done and not state.session_id:
                log.debug("No new sessions; sleeping %ds", POLL_INTERVAL_SEC)
            elif state.done:
                log.info("Analysis complete for session %s", state.session_id)
            else:
                log.warning("Graph exited without setting done=True")
        except Exception:
            log.exception("Unhandled error in analysis loop")

        await asyncio.sleep(POLL_INTERVAL_SEC)


def main() -> None:
    try:
        asyncio.run(_run_loop())
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
