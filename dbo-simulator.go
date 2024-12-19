package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	metricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	v1proto "go.opentelemetry.io/proto/otlp/common/v1"
	otlpmetrics "go.opentelemetry.io/proto/otlp/metrics/v1"
	v1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	protobuf "google.golang.org/protobuf/proto"
)

type TransparentBinaryCodec struct{}

func (cb TransparentBinaryCodec) Name() string {
	return "binary-send-proto-receive"
}

func (cb TransparentBinaryCodec) Marshal(v interface{}) ([]byte, error) {
	return v.([]byte), nil
}

func (cb TransparentBinaryCodec) Unmarshal(data []byte, v interface{}) error {
	return encoding.GetCodec(proto.Name).Unmarshal(data, v)
}

func main() {

	metrics := metricspb.ExportMetricsServiceRequest{}
	metrics.ResourceMetrics = []*otlpmetrics.ResourceMetrics{
		{
			Resource: &v1.Resource{
				Attributes: []*v1proto.KeyValue{{
					Key: "sw.entity.databaseinstance.id",
					Value: &v1proto.AnyValue{
						Value: &v1proto.AnyValue_StringValue{
							StringValue: "e-1778907202371198976",
						},
					},
				}},
			},
			ScopeMetrics: []*otlpmetrics.ScopeMetrics{
				{
					Scope: &v1proto.InstrumentationScope{
						Name:    "DBO",
						Version: "1",
					},
					Metrics: []*otlpmetrics.Metric{
						{
							Name:        "dbo.host.queries.testperfmetric",
							Description: "TestMetric",
							Unit:        "count",
							Data: &otlpmetrics.Metric_Gauge{
								Gauge: &otlpmetrics.Gauge{
									DataPoints: []*otlpmetrics.NumberDataPoint{
										{

											TimeUnixNano: uint64(time.Now().UnixNano()),
											Value: &otlpmetrics.NumberDataPoint_AsInt{
												AsInt: 12345,
											},
											Attributes: []*v1proto.KeyValue{
												{
													Key: "dummyTestAttribute",
													Value: &v1proto.AnyValue{
														Value: &v1proto.AnyValue_StringValue{
															StringValue: "dummyTestValue",
														},
													},
												},
											},
										},
									},
								},
							},
							Metadata: []*v1proto.KeyValue{
								{
									Key: "dummyTestAttribute1",
									Value: &v1proto.AnyValue{
										Value: &v1proto.AnyValue_StringValue{
											StringValue: "dummyTestValue1",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	fmt.Println(metrics.String())
	msg, err := protobuf.Marshal(&metrics)
	if err != nil {
		log.Fatalln("Marshalling err: ", err)
	}

	otelEndpoint := "otel-collector.dc-01.dev-ssp.solarwinds.com:443"
	path := "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	//path := "opentelemetry.proto.collector.metrics.v1.MetricsService.Export"
	token := ""
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)

	response := metricspb.ExportMetricsServiceResponse{}
	opt := grpc.WithTransportCredentials(insecure.NewCredentials())
	opts := []grpc.DialOption{}
	opts = append(opts, opt)
	opts = append(opts,
		grpc.WithDefaultCallOptions(grpc.ForceCodec(TransparentBinaryCodec{})),
	)

	caPool, err := extendWithCustomCA("")
	if err != nil {
		log.Fatalln("CA Pool ", err)
	}

	opts = append(opts,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    caPool, // should stay nil when rootCAPath is not set
			MinVersion: tls.VersionTLS12,
			VerifyConnection: func(_ tls.ConnectionState) error {
				// TODO: Implement custom validation to be run after the builtin one (NH-9048)
				return nil
			},
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				// TODO: Implement custom validation to be run after the builtin one (NH-9048)
				return nil
			},
		})),
		grpc.WithDefaultCallOptions(
			grpc.UseCompressor(gzip.Name),
		),
	)

	grpcClient, err := grpc.NewClient(otelEndpoint, opts...)
	if err != nil {
		log.Fatalln("grpc new client err: ", err)
	}
	//err = grpcClient.Invoke(ctx, path, metrics.ProtoReflect(), &response)
	err = grpcClient.Invoke(ctx, path, msg, &response)
	log.Println(response.String())
	if err != nil {
		s, errDetailsAvailable := status.FromError(err)
		if errDetailsAvailable {

			log.Println(s.Message())
			log.Println(
				s.Message(),
				s.Details(),
				s.Proto().Code,
				s.Proto().Details,
				s.Proto().Message,
			)
		}
		log.Fatalln("grpc invoke err: ", err)
	}

}

func extendWithCustomCA(rootCAPath string) (*x509.CertPool, error) {
	if rootCAPath == "" {
		return nil, nil // implies using the default rootCAs later on
	}

	var caPool *x509.CertPool
	var err error

	caPool, err = x509.SystemCertPool()

	if err != nil {
		return nil, fmt.Errorf("getting system CAs failed: %w", err)
	}

	customCA, err := os.ReadFile(filepath.Clean(rootCAPath))
	if err != nil {
		return nil, err
	}

	if !caPool.AppendCertsFromPEM(customCA) {
		return nil, errors.New("failed to include a custom CA certificate")
	}

	return caPool, nil
}
