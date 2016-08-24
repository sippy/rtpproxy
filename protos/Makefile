all: out/crypto_pb2.py out/stream_info_pb2.py out/rtpp_response.py

out/crypto_pb2.py: crypto.proto stream_info.proto
	protoc --python_out=out crypto.proto

out/stream_info_pb2.py: stream_info.proto
	protoc --python_out=out stream_info.proto

out/rtpp_response.py: rtpp_response.proto
	protoc --python_out=out rtpp_response.proto

clean:
	rm -f out/crypto_pb2.py out/stream_info_pb2.py
