using System;

namespace PROSCANNERCONT.Services
{
    public static class AIProviderService
    {
        private static string _current = "openai-gpt35";

        public static string Current => _current;

        /// <summary>Fired on the calling thread whenever the provider changes.</summary>
        public static event EventHandler<string>? ProviderChanged;

        public static void Set(string providerTag)
        {
            if (_current == providerTag) return;
            _current = providerTag;
            ProviderChanged?.Invoke(null, providerTag);
        }

        // Friendly display info for each provider tag
        public static (string Name, string Model, string Icon) Info(string tag) => tag switch
        {
            "openai-gpt4"  => ("OpenAI",     "GPT-4",     "Robot"),
            "anthropic"    => ("Claude",      "Anthropic", "Brain"),
            _              => ("OpenAI",     "GPT-3.5",   "Robot"),
        };
    }
}
