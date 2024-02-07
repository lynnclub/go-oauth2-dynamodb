# DynamoDB Storage for OAuth 2.0

> Based on the https://github.com/contamobi/go-oauth2-dynamodb

[![License][License-Image]][License-Url]

## Install

``` bash
$ go get -u github.com/lynnclub/go-oauth2-dynamodb
```

## Usage (specifying credentials)

``` go
package main

import (
	"github.com/lynnclub/go-oauth2-dynamodb"
	"github.com/go-oauth2/oauth2/v4/manage"
)

func main() {
	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(
		dynamo.NewTokenStoreV4(dynamo.NewConfig(
			"us-east-1", // AWS Region
			"http://localhost:8000", // AWS DynamoDB Endpoint
			"AKIA*********", // AWS Access Key
			"*************", // AWS Secret
                        "oauth2_basic", // Oauth2 basic table name
			"oauth2_access", // Oauth2 access table name
			"oauth2_refresh", // Oauth2 refresh table name
		)),
	)
	// ...
}
```

## Usage (with IAM Role configured for ec2 or Lambda)

``` go
package main

import (
	"github.com/lynnclub/go-oauth2-dynamodb"
	"github.com/go-oauth2/oauth2/v4/manage"
)

func main() {
	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(
		dynamo.NewTokenStoreV4(dynamo.NewConfig(
			"us-east-1", // AWS Region
			"", // Emtpy
			"", // Emtpy
			"", // Emtpy
			"oauth2_basic", // Oauth2 basic table name
                        "oauth2_access", // Oauth2 access table name
                        "oauth2_refresh", // Oauth2 refresh table name

		)),
	)
	// ...
}
```

## Run tests

### Start dynamodb local
``` 
java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb 
```

### Export env variables
```
export AWS_REGION=us-east-1
export DYNAMODB_ENDPOINT='http://localhost:8000'
export AWS_ACCESS_KEY=AKIA******
export AWS_SECRET=**************
```

### Run tests
```
go test
```

## MIT License

```
Copyright (c) 2018 Conta.MOBI
```

[License-Url]: http://opensource.org/licenses/MIT
[License-Image]: https://img.shields.io/npm/l/express.svg
