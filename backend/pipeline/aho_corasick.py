from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field


@dataclass
class Node:
    edges: dict[str, int] = field(default_factory=dict)
    failure: int = 0
    output: list[str] = field(default_factory=list)


class AhoCorasick:
    def __init__(self, phrases: Iterable[str]) -> None:
        self.nodes = [Node()]
        for phrase in dict.fromkeys(phrases):
            if not phrase:
                raise ValueError("Empty phrases are unsupported.")
            index = 0
            for char in phrase:
                if char not in self.nodes[index].edges:
                    self.nodes[index].edges[char] = len(self.nodes)
                    self.nodes.append(Node())
                index = self.nodes[index].edges[char]
            self.nodes[index].output.append(phrase)
        queue = deque(self.nodes[0].edges.values())
        while queue:
            index = queue.popleft()
            for char, child in self.nodes[index].edges.items():
                queue.append(child)
                fallback = self.nodes[index].failure
                while fallback and char not in self.nodes[fallback].edges:
                    fallback = self.nodes[fallback].failure
                target = self.nodes[fallback].edges.get(char, 0)
                self.nodes[child].failure = target
                self.nodes[child].output.extend(self.nodes[target].output)

    def find(self, text: str) -> Iterator[tuple[int, str]]:
        index = 0
        for end, char in enumerate(text):
            while index and char not in self.nodes[index].edges:
                index = self.nodes[index].failure
            index = self.nodes[index].edges.get(char, 0)
            for phrase in self.nodes[index].output:
                yield end + 1 - len(phrase), phrase
