"""Build and compile the LangGraph analysis pipeline."""
from langgraph.graph import StateGraph, END

from .state import SessionAnalysisState
from .nodes.ingest import ingest_node
from .nodes.classify import classify_node
from .nodes.enrich import enrich_node
from .nodes.summarize import summarize_node
from .nodes.output import output_node


def _should_continue(state: SessionAnalysisState) -> str:
    if state.done or state.error:
        return "output"
    return "classify"


def build_graph():
    graph = StateGraph(SessionAnalysisState)

    graph.add_node("ingest",    ingest_node)
    graph.add_node("classify",  classify_node)
    graph.add_node("enrich",    enrich_node)
    graph.add_node("summarize", summarize_node)
    graph.add_node("output",    output_node)

    graph.set_entry_point("ingest")

    graph.add_conditional_edges(
        "ingest",
        _should_continue,
        {"classify": "classify", "output": "output"},
    )
    graph.add_edge("classify",  "enrich")
    graph.add_edge("enrich",    "summarize")
    graph.add_edge("summarize", "output")
    graph.add_edge("output",    END)

    return graph.compile()
