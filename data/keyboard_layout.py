"""
data/keyboard_layout.py
Adjacences qwerty -- horizontales uniquement (decision : voir patterns.py / journal).

ADJACENCY : dict {touche: [voisins horizontaux sur la meme ligne]}
Permet de detecter des sequences type "qwerty", "asdf", "1234" -- pas les
sequences verticales/diagonales (ex. "qaz"), volontairement hors scope MVP.
"""

ROWS = [
    "1234567890-=",
    "qwertyuiop[]",
    "asdfghjkl;'",
    "zxcvbnm,./",
]


def _build_adjacency():
    adjacency = {}
    for row in ROWS:
        for i, char in enumerate(row):
            neighbors = []
            if i > 0:
                neighbors.append(row[i - 1])
            if i < len(row) - 1:
                neighbors.append(row[i + 1])
            adjacency[char] = neighbors
    return adjacency


ADJACENCY = _build_adjacency()


def get_neighbors(char: str) -> list:
    return ADJACENCY.get(char.lower(), [])