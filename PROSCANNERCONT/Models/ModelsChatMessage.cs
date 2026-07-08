namespace PROSCANNERCONT.Models
{
    public class ChatMessage
    {
        public string Message { get; set; }
        public bool IsUser { get; set; }

        public ChatMessage(string message, bool isUser)
        {
            Message = message;
            IsUser = isUser;
        }
    }
}