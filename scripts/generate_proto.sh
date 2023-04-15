cd api/proto/contract || cd ../api/proto/contract || exit
rm -rf ../implementation
mkdir ../implementation
protoc \
  --go_out=../implementation \
  --go_opt=paths=source_relative \
  --go-grpc_out=../implementation \
  --go-grpc_opt=paths=source_relative \
  */*.proto
