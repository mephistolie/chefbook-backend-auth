module github.com/mephistolie/chefbook-backend-auth

go 1.20

require (
	github.com/google/uuid v1.3.0
	github.com/jackc/pgx/v5 v5.3.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/mephistolie/chefbook-backend-auth/api v0.0.0
	github.com/mephistolie/chefbook-backend-common/firebase v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/hash v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/log v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/mail v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/random v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/responses v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/shutdown v0.0.0-20230416191649-175445efa564
	github.com/mephistolie/chefbook-backend-common/tokens v0.0.0-20230416191649-175445efa564
	github.com/mssola/useragent v1.0.0
	github.com/peterbourgon/ff/v3 v3.3.0
	golang.org/x/oauth2 v0.7.0
	google.golang.org/grpc v1.54.0
	google.golang.org/protobuf v1.30.0
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/compute v1.19.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/firestore v1.9.0 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	cloud.google.com/go/longrunning v0.4.1 // indirect
	cloud.google.com/go/storage v1.30.1 // indirect
	firebase.google.com/go/v4 v4.11.0 // indirect
	github.com/MicahParks/keyfunc v1.9.0 // indirect
	github.com/go-gomail/gomail v0.0.0-20160411212932-81ebce5c23df // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/s2a-go v0.1.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.8.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/lib/pq v1.10.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.10 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.8.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.118.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/appengine/v2 v2.0.2 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
)

replace github.com/mephistolie/chefbook-backend-auth/api => ./api
