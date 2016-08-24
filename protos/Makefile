all: out/crypto_pb2.py out/sinfo_pb2.py

out/crypto_pb2.py: crypto.proto sinfo.proto
	protoc --python_out=out crypto.proto

out/sinfo_pb2.py: sinfo.proto
	protoc --python_out=out sinfo.proto
