package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/rafawilliner/tokenalert_utils-go/src/rest_errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	Client *resty.Client
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func init() {
	godotenv.Load(".env")
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {

	var atResponse *accessToken
	var respError error

	response, err := Client.R().
		SetResult(&atResponse).
		SetError(&respError).
		Get(fmt.Sprintf("%s/access_token", os.Getenv("access_token_api_url")))

	if err != nil {
		panic(err)
	}

	if response.IsError() {
		switch response.StatusCode() {
		case 400:
			return nil, rest_errors.NewBadRequestError("invalid restclient response when trying to login user")

		case 404:
			return nil, rest_errors.NewNotFoundError("invalid restclient response when trying to login user")
		default:
			return nil, rest_errors.NewInternalServerError("invalid restclient response when trying to login user", errors.New("restclient error"))
		}
	}

	return atResponse, nil
}
