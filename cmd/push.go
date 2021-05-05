package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Insecure bool = false
var SkipTLS bool = false

func init() {
	rootCmd.AddCommand(pushCmd)

	pushCmd.PersistentFlags().BoolVarP(&Insecure, "insecure", "", false, "Disable TLS certificate verification (for development)")
	pushCmd.PersistentFlags().BoolVarP(&SkipTLS, "skip-tls", "", false, "Disable HTTPS and use HTTP (for development)")
}

type UploadTargetResponse struct {
	UploadTo struct {
		URL    string            `json:"url"`
		Fields map[string]string `json:"fields"`
	} `json:"upload_to"`

	ClaimURL string `json:"claim_url"`
}

type UploadClaimResponse struct {
	URL   string `json:"url"`
	Query string `json:"query"`
}

func transportForUrl(baseUrl string) (string, *http.Client) {
	var url string
	var client *http.Client

	if SkipTLS {
		url = "http://" + baseUrl
	} else {
		url = "https://" + baseUrl
	}

	if Insecure {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client = &http.Client{Transport: transport}
	} else {
		client = &http.Client{}
	}

	return url, client
}

func beginPush(baseUrl string, pushToken string) (*UploadTargetResponse, error) {
	url, client := transportForUrl(baseUrl)
	req, err := http.NewRequest("POST", url+"/api/push", nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+pushToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not perform request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Could not read body: %v", err)
	}

	out := &UploadTargetResponse{}
	err = json.Unmarshal(body, out)
	if err != nil {
		return nil, fmt.Errorf("Could not parse JSON: %v", err)
	}

	return out, nil
}

func claimPush(baseUrl string, claimUrl string, pushToken string) (*UploadClaimResponse, error) {
	_, client := transportForUrl(baseUrl)
	req, err := http.NewRequest("POST", claimUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+pushToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not perform request: %v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Could not read body: %v", err)
	}

	out := &UploadClaimResponse{}
	err = json.Unmarshal(body, out)
	if err != nil {
		return nil, fmt.Errorf("Could not parse JSON: %v", err)
	}

	return out, nil
}

var pushCmd = &cobra.Command{
	Use:   "push <url> <file>",
	Short: "Push a capture file to the web UI at the given path",
	Args:  cobra.ExactValidArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		remoteHost := args[0]
		captureFile := args[1]
		configKey := strings.Replace(remoteHost, ".", "_", -1)

		pushToken := viper.GetString("push_tokens." + configKey)
		if pushToken == "" {
			fmt.Printf("No push token configured for %v\n", remoteHost)
			fmt.Printf("\n")
			fmt.Printf("Try logging in first: tracecap login %v\n", remoteHost)
			return
		}

		captureFileContent, err := ioutil.ReadFile(captureFile)
		if err != nil {
			fmt.Printf("Could not read trace file: %v\n", err)
			return
		}

		uploadTarget, err := beginPush(remoteHost, pushToken)
		if err != nil {
			fmt.Printf("Error beginning push: %v\n", err)
			return
		}

		fmt.Printf("Uploading tcap...\n")

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		for k, v := range uploadTarget.UploadTo.Fields {
			err := writer.WriteField(k, v)
			if err != nil {
				fmt.Printf("Error creating form fields: %v\n", err)
				return
			}
		}

		part, err := writer.CreateFormFile("file", "capture.tcap")
		if err != nil {
			fmt.Printf("Error creating form file: %v\n", err)
			return
		}
		_, err = part.Write(captureFileContent)
		if err != nil {
			fmt.Printf("Error writing file: %v\n", err)
			return
		}

		writer.Close()

		req, _ := http.NewRequest("POST", uploadTarget.UploadTo.URL, body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error uploading file: %v\n", err)
			return
		}

		if resp.StatusCode != 204 {
			fmt.Printf("Upload returned status code %v rather than expected 204.\n", resp.StatusCode)
			return
		}

		// now we can claim it!
		claimResponse, err := claimPush(remoteHost, uploadTarget.ClaimURL, pushToken)
		if err != nil {
			fmt.Printf("Error claiming uploading file: %v\n", err)
			return
		}

		fmt.Printf("Trace has been uploaded successfully! You can view it at:\n\n")
		fmt.Printf("   URL: %v\n\n", claimResponse.URL)
		fmt.Printf("   Query: %v\n\n", claimResponse.Query)
	},
}
