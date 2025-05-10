package model8

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	// "strings"
)

type DiscordSticker struct {
}

type DiscordWelcomeScreenChannel struct {
	Channel_id  string `json:"channel_id,omitempty"`
	Description string `json:"description,omitempty"`
	Emoji_id    string `json:"emoji_id,omitempty"`
	Emoji_name  string `json:"emoji_name,omitempty"`
}

type DiscordWelcomeScreen struct {
	Description      string                        `json:"description,omitempty"`
	Welcome_channels []DiscordWelcomeScreenChannel `json:"welcome_channels,omitempty"`
}

type DiscordEmoji struct {
	Id             string        `json:"id,omitempty"`
	Name           string        `json:"name,omitempty"`
	Roles          []DiscordRole `json:"roles,omitempty"`
	User           DiscordUser   `json:"user,omitempty"`
	Require_colons bool          `json:"require_colons,omitempty"`
	Managed        bool          `json:"managed,omitempty"`
	Animated       bool          `json:"animated,omitempty"`
	Available      bool          `json:"available,omitempty"`
}

type DiscordRoleTag struct {
	Bot_id                  string `json:"bot_id,omitempty"`
	Integration_id          string `json:"integration_id,omitempty"`
	Subscription_listing_id string `json:"subscription_listing_id,omitempty"`
}

type DiscordRole struct {
	Id            string         `json:"id,omitempty"`
	Name          string         `json:"name,omitempty"`
	Color         int            `json:"color,omitempty"`
	Hoist         bool           `json:"hoist,omitempty"`
	Icon          string         `json:"icon,omitempty"`
	Unicode_emoji string         `json:"unicode_emoji,omitempty"`
	Position      int            `json:"position,omitempty"`
	Permissions   string         `json:"permissions,omitempty"`
	Managed       bool           `json:"managed,omitempty"`
	Mentionable   bool           `json:"mentionable,omitempty"`
	Tags          DiscordRoleTag `json:"tags,omitempty"`
	Flags         int            `json:"flags,omitempty"`
}

type DiscordChannel struct {
}

type DiscordGuild struct {
	Id                            string               `json:"id,omitempty"`
	Name                          string               `json:"name,omitempty"`
	Icon                          string               `json:"icon,omitempty"`
	Icon_hash                     string               `json:"icon_hash,omitempty"`
	Splash                        string               `json:"splash,omitempty"`
	Discovery_splash              string               `json:"discovery_splash,omitempty"`
	Owner                         bool                 `json:"owner,omitempty"`
	Owner_id                      string               `json:"owner_id,omitempty"`
	Permissions                   string               `json:"permissions,omitempty"`
	Region                        string               `json:"region,omitempty"`
	Afk_channel_id                string               `json:"afk_channel_id,omitempty"`
	Afk_timeout                   int                  `json:"afk_timeout,omitempty"`
	Widget_enabled                bool                 `json:"widget_enabled,omitempty"`
	Widget_channel_id             string               `json:"widget_channel_id,omitempty"`
	Verification_level            int                  `json:"verification_level,omitempty"`
	Default_message_notifications int                  `json:"default_message_notifications,omitempty"`
	Explicit_content_filter       int                  `json:"explicit_content_filter,omitempty"`
	Roles                         []DiscordRole        `json:"roles,omitempty"`
	Emojis                        []DiscordEmoji       `json:"emojis,omitempty"`
	Features                      []string             `json:"features,omitempty"`
	Mfa_level                     int                  `json:"mfa_level,omitempty"`
	Application_id                string               `json:"application_id,omitempty"`
	System_channel_id             string               `json:"system_channel_id,omitempty"`
	System_channel_flags          int                  `json:"system_channel_flags,omitempty"`
	Rules_channel_id              string               `json:"rules_channel_id,omitempty"`
	Max_presences                 int                  `json:"max_presences,omitempty"`
	Max_members                   int                  `json:"max_members,omitempty"`
	Vanity_url_code               string               `json:"vanity_url_code,omitempty"`
	Description                   string               `json:"description,omitempty"`
	Banner                        string               `json:"banner,omitempty"`
	Premium_tier                  int                  `json:"premium_tier,omitempty"`
	Premium_subscription_count    int                  `json:"premium_subscription_count,omitempty"`
	Preferred_locale              string               `json:"preferred_locale,omitempty"`
	Public_updates_channel_id     string               `json:"public_updates_channel_id,omitempty"`
	Max_video_channel_users       int                  `json:"max_video_channel_users,omitempty"`
	Max_stage_video_channel_users int                  `json:"max_stage_video_channel_users,omitempty"`
	Approximate_member_count      int                  `json:"approximate_member_count,omitempty"`
	Approximate_presence_count    int                  `json:"approximate_presence_count,omitempty"`
	Welcome_screen                DiscordWelcomeScreen `json:"welcome_screen,omitempty"`
	Nsfw_level                    int                  `json:"nsfw_level,omitempty"`
	Stickers                      DiscordSticker       `json:"stickers,omitempty"`
	Premium_progress_bar_enabled  bool                 `json:"premium_progress_bar_enabled,omitempty"`
	Safety_alerts_channel_id      string               `json:"safety_alerts_channel_id,omitempty"`
}

type DiscordUser struct {
	Id                string `json:"id,omitempty"`
	Username          string `json:"username,omitempty"`
	Discriminator     string `json:"discriminator,omitempty"`
	Global_name       string `json:"global_name,omitempty"`
	Avatar            string `json:"avatar,omitempty"`
	Bot               bool   `json:"bot,omitempty"`
	System            bool   `json:"system,omitempty"`
	Mfa_enabled       bool   `json:"mfa_enabled,omitempty"`
	Banner            string `json:"banner,omitempty"`
	Accent_color      int    `json:"accent_color,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Verified          bool   `json:"verified,omitempty"`
	Email             string `json:"email,omitempty"`
	Flags             int    `json:"flags,omitempty"`
	Premium_type      int    `json:"premium_type,omitempty"`
	Public_flags      int    `json:"public_flags,omitempty"`
	Avatar_decoration string `json:"avatar_decoration,omitempty"`
}

type DiscordWebhook struct {
	Id             string      `json:"id,omitempty"`
	Ttype          int         `json:"type,omitempty"`
	Guild_id       string      `json:"guild_id,omitempty"`
	Channel_id     string      `json:"channel_id,omitempty"`
	User           DiscordUser `json:"user,omitempty"`
	Name           string      `json:"name,omitempty"`
	Avatar         string      `json:"avatar,omitempty"`
	Token          string      `json:"token,omitempty"`
	Application_id string      `json:"application_id,omitempty"`
	// Source_guild   DiscordGuild   `json:"source_guild"`
	// Source_channel DiscordChannel `json:"source_channel"`
	Url string `json:"url,omitempty"`
}

type CustomMessagesFinding struct {
	Template    string `json:"template,omitempty"`
	Type        string `json:"type,omitempty"`
	Info        string `json:"info,omitempty"`
	Description string `json:"description,omitempty"`
	Found       string `json:"found,omitempty"`
}

type CustomMessagesSeverity struct {
	Severity     string                  `json:"severity,omitempty"`
	Per_severity []CustomMessagesFinding `json:"per_severity,omitempty"`
}

type CustomMessagesPort struct {
	Port     string                   `json:"port,omitempty"`
	Per_port []CustomMessagesSeverity `json:"per_port,omitempty"`
}

type CustomMessagesHost struct {
	Host     string               `json:"host,omitempty"`
	Per_host []CustomMessagesPort `json:"per_host,omitempty"`
}

type NaabuM8Discord struct {
	APIBaseURL   string
	webhookURL   string
	WebhookID    string
	WebhookName  string
	WebhookToken string
	BotToken     string
	ChannelID    string
	ChatMessages []CustomMessagesHost
}

func NewModel8Discord8(whURL, whID, wName, wToken, bToken string) Model8Discord8Interface {
	return &NaabuM8Discord{
		APIBaseURL:   "https://discord.com/api",
		webhookURL:   whURL,
		WebhookID:    whID,
		WebhookName:  wName,
		WebhookToken: wToken,
		BotToken:     bToken,
		ChannelID:    "",
		ChatMessages: nil,
	}
}

func (n *NaabuM8Discord) InitialiseChannelID() error {
	url := n.webhookURL
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		defer resp.Body.Close()

		// responseBody, err := ioutil.ReadAll(resp.Body)
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println(string(responseBody))
			return err
		}
		log.Println(string(responseBody))
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error IO reading body")
		return err
	}
	var webhookObj DiscordWebhook
	err = json.Unmarshal(responseBody, &webhookObj)
	if err != nil {
		log.Println("Can not unmarshal JSON")
		return err
	}
	n.ChannelID = webhookObj.Channel_id
	return nil
}

func (n *NaabuM8Discord) SetWebHook(url, id, name string) {
	n.webhookURL = url
	n.ChannelID = id
	n.WebhookName = name
}

func (n *NaabuM8Discord) SetBot(token string) {
	n.BotToken = token
}

func (n *NaabuM8Discord) GetChannelID() string {
	return n.ChannelID
}

func (n *NaabuM8Discord) GetBotToken() string {
	return n.BotToken
}

func (n *NaabuM8Discord) AddChatMessages(c CustomMessagesHost) []CustomMessagesHost {
	n.ChatMessages = append(n.ChatMessages, c)
	return n.ChatMessages
}
