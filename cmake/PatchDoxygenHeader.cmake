file(READ "${HEADER}" CONTENT)

string(REPLACE
        "image/x-icon"
        "image/svg+xml"
        CONTENT "${CONTENT}"
)

file(WRITE "${HEADER}" "${CONTENT}")
