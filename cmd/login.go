package cmd

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(loginCmd)
}

var loginCmd = &cobra.Command{
	Use:   "login <url>",
	Short: "Login to the web UI for a given path",
	Args:  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pushToken := ""
		prompt := &survey.Password{
			Message: "Enter your push token",
		}
		survey.AskOne(prompt, &pushToken)

		remoteHost := args[0]
		configKey := strings.Replace(remoteHost, ".", "_", -1)

		var pushTokens map[string]interface{}
		if pushTokens_, ok := viper.Get("push_tokens").(map[string]interface{}); ok {
			pushTokens = pushTokens_
		} else {
			pushTokens = map[string]interface{}{}
		}
		pushTokens[configKey] = pushToken
		viper.Set("push_tokens", pushTokens)

		err := viper.SafeWriteConfig()
		if err != nil {
			viper.WriteConfig()
		}

		fmt.Printf("\nSaved token for %v.\n", args[0])
	},
}
