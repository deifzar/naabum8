/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"deifzar/naabum8/pkg/api8"
	"deifzar/naabum8/pkg/log8"
	"deifzar/naabum8/pkg/notification8"
	"deifzar/naabum8/pkg/utils"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// launchCmd represents the launch command
var launchCmd = &cobra.Command{
	Use:   "launch",
	Short: "Launch the ASSM API service, indicating the IP address and port to bind.",
	// 	Long: `A longer description that spans multiple lines and likely contains examples
	// and usage of using your command. For example:
	// Cobra is a CLI library for Go that empowers applications.
	// This application is a tool to generate the needed files
	// to quickly create a Cobra application.`,
	Args: cobra.MatchAll(cobra.MaximumNArgs(2), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		ipFlag, err := cmd.Flags().GetString("ip")
		portFlag, err2 := cmd.Flags().GetInt("port")
		if err != nil || err2 != nil {
			log8.BaseLogger.Debug().Stack().Msg(err.Error())
			log8.BaseLogger.Debug().Stack().Msg(err2.Error())
			log8.BaseLogger.Fatal().Msg("Error in `Launch` command line with some of the arguments.")
			return err
		} else {
			if !utils.IsValidIPAddress(ipFlag) {
				log8.BaseLogger.Fatal().Msg("Error in `Launch` command line. Invalid IP address.")
				return errors.New("no valid IP address")
			}
			if portFlag < 8000 || portFlag > 9000 {
				log8.BaseLogger.Fatal().Msg("Error in `Launch` command line. Error port range: 8000 - 8999.")
				return errors.New("port number between 8000 and 8999")
			}
			address := ipFlag + ":" + fmt.Sprint(portFlag)
			var a api8.Api8
			err := a.Init()
			if err != nil {
				log8.BaseLogger.Debug().Stack().Msg(err.Error())
				log8.BaseLogger.Fatal().Msg("Error in `Launch` command line when initialising the API endpoint.")
				notification8.Helper.PublishSysErrorNotification("Error in `Launch` command line when initialising the API endpoint", "urgent", "naabum8")
				return err
			}
			a.Routes()
			a.Run(address)
			log8.BaseLogger.Info().Msg("API service successfully running in " + address)
			return nil
		}
	},
}

func init() {
	rootCmd.AddCommand(launchCmd)

	// Here you will define your flags and configuration settings.
	launchCmd.Flags().String("ip", "0.0.0.0", "IP address bind to the service. By default, it will listen to all IP addresses.")
	launchCmd.Flags().Int("port", 8001, "Port bind to the service. By default, it will listen to port 8001.")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// launchCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// launchCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
