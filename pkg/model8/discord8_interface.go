package model8

type Model8Discord8Interface interface {
	InitialiseChannelID() error
	SetWebHook(string, string, string)
	SetBot(string)
	GetChannelID() string
	GetBotToken() string
	AddChatMessages(CustomMessagesHost) []CustomMessagesHost
}
