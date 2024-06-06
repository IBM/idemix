module github.com/IBM/idemix

go 1.22.6

require (
	github.com/IBM/idemix/bccsp/schemes/aries v0.0.0-20240820063231-23c21a416ee1
	github.com/IBM/idemix/bccsp/schemes/weak-bb v0.0.0-20240820063231-23c21a416ee1
	github.com/IBM/idemix/bccsp/types v0.0.0-20240820063231-23c21a416ee1
	github.com/IBM/mathlib v0.0.3-0.20231011094432-44ee0eb539da
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/golang/protobuf v1.5.4
	github.com/hyperledger/aries-bbs-go v0.0.0-20240528084656-761671ea73bc
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.3
	github.com/onsi/ginkgo/v2 v2.13.2
	github.com/onsi/gomega v1.31.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	github.com/sykesm/zap-logfmt v0.0.4
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.65.0
)

require (
	github.com/alecthomas/units v0.0.0-20240626203959-61d1e3462e30 // indirect
	github.com/bits-and-blooms/bitset v1.13.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.13.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20230602173724-9e02669dceb2 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/IBM/idemix/bccsp/types => ./bccsp/types/

replace github.com/IBM/idemix/bccsp/schemes/aries => ./bccsp/schemes/aries/
