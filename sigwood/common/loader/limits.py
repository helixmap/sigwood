"""Hard fold-foundation limits shared by reader, types, and execution."""

MAX_CHUNK_ROWS = 65_536
MAX_CHUNK_DECODED_BYTES = 32 * 1024 * 1024
MAX_LOGICAL_RECORD_BYTES = 1024 * 1024
# Ceiling for a WHOLE-DOCUMENT logical record on the one family whose
# legitimate shape is a single multi-megabyte JSON document (a CloudTrail
# delivery is one `{"Records":[...]}` line). Twice the chunk decoded ceiling:
# it bounds retained parse state at the order the chunk path already accepts,
# and a document over it skips with the ordinary oversize disclosure.
MAX_LOGICAL_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_FILE_DELTA_BYTES = 256 * 1024 * 1024
