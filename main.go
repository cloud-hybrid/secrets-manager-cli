package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func getSecret() string {
	secretName := "Organization/Environment/System/Service/Common-Name"
	region := "us-east-2"

	// Create a Secrets Manager client
	svc := secretsmanager.New(session.New(), aws.NewConfig().WithRegion(region))

	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)

	if err != nil {
		if signal, ok := err.(awserr.Error); ok {
			switch signal.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				fmt.Println("[Error] (ErrCodeDecryptionFailure): Exception during Decryption of KMS Key")

				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, signal.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				fmt.Println("[Error] (ErrCodeInternalServiceError): AWS Service Exception")
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, signal.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				fmt.Println("[Error] (ErrCodeInvalidParameterException): Exception via Invalid Parameter")
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, signal.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				fmt.Println("[Error] (ErrCodeInvalidRequestException): Exception forming API Request")
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, signal.Error())
			case secretsmanager.ErrCodeResourceNotFoundException:
				fmt.Println("[Error] (ErrCodeResourceNotFoundException): No Resource Found")
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, signal.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var data string = ""
	if result.SecretString != nil {
		data = *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))

		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)

		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
			os.Exit(1)
		}

		data = string(decodedBinarySecretBytes[:len])
	}

	return data
}

func main() { fmt.Println(getSecret()) }