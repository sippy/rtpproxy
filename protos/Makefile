.for proto in crypto stream_info rtpp_response network rtpp_request rtpp_id \
    session_info
__ALL_TGTS+=out/${proto}_pb2.py
CLEANFILES+=out/${proto}_pb2.py*
out/${proto}_pb2.py: ${proto}.proto
	protoc --python_out=out ${.ALLSRC}
	protoc-c --c_out=out ${.ALLSRC}
.endfor

__ALL_TGTS := ${__ALL_TGTS}
all: ${__ALL_TGTS} 

clean:
	rm -f ${CLEANFILES}
