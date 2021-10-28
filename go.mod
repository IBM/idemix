module github.com/IBM/idemix

go 1.16

require (
	github.com/IBM/mathlib v0.0.0-20210928081244-f5486459a290
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210912230133-d1bdfacee922 // indirect
	github.com/golang/protobuf v1.3.3
	github.com/google/addlicense v1.0.0 // indirect
	github.com/hyperledger/fabric-protos-go v0.0.0-20210911123859-041d13f0980c
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.1-0.20210116013205-6990a05d54c2 // includes ErrorContains
	github.com/sykesm/zap-logfmt v0.0.2
	go.uber.org/zap v1.16.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	google.golang.org/grpc v1.31.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/onsi/gomega => github.com/onsi/gomega v1.9.0
