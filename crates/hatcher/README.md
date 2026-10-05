# Hatcher

Urbit Hoon 135 parser, based on Hatch. Hatch's Nockchain parser remains in
`crates/hatch`.

`native_file_parser` reads Clay import headers and the expression body.
`native_parser` reads an expression. Byte-source helpers preserve non-UTF-8
literal octets; the AST supports arbitrary-size atoms and axes.

The parser is derived from Chris Allen's Hatch at Nockchain revision
`73877be29bd1fafeeade1be7b95aebb0f64d8382`, under MIT OR Apache-2.0. See the
included licenses.
