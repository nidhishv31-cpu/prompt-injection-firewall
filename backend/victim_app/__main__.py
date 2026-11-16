"""Run a single local demo turn."""

from argparse import ArgumentParser

from backend.victim_app.chat import Event, Turn, create_backend
from backend.victim_app.documents import DOCUMENTS


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("text", help="Text for the demo turn")
    parser.add_argument("--event", type=Event, choices=list(Event))
    parser.add_argument("--document", action="append", choices=sorted(DOCUMENTS))
    args = parser.parse_args()
    try:
        chatbot = create_backend()
    except ValueError as error:
        parser.error(str(error))
    documents = tuple(DOCUMENTS[slug] for slug in args.document or ())
    reply = chatbot.reply(Turn(text=args.text, event=args.event), documents)
    print(reply.text)


if __name__ == "__main__":
    main()
