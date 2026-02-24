# 🦅 nest/llm_advisor.py
# ---------------------------------------------------------
# SentinelHawk — LLM Advisor (Summarization + Recommendations)
# ---------------------------------------------------------

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from secrets_ import API_KEY

class LLMAdvisor:

    def __init__(self, stream=False):
        if OpenAI and API_KEY != "YOUR_OPENAI_API_KEY":
            self.client = OpenAI(api_key=API_KEY)
        else:
            self.client = None
        self.stream = stream

    def summarize(self, event, risk):
        """
        Summarizes the event, justifies risk, and provides recommended action.
        """
        if not self.client:
            return {
                "summary": "LLM Disabled or Misconfigured", 
                "justification": "Risk calculated by static heuristics.", 
                "recommended_action": "Refer to playbook."
            }

        prompt = f"""
        You are a SOC analyst AI.
        Event Details: {event}
        Risk Score: {risk}

        Provide:
        1. Threat Summary
        2. Risk Justification
        3. Recommended Action (actionable for SOC)
        Format response as JSON:
        {{
            "summary": "...",
            "justification": "...",
            "recommended_action": "..."
        }}
        """

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o", 
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                stream=self.stream
            )
            
            # Since stream logic in the original was minimal, we assume non-streaming for simplicity unless complex
            if self.stream:
                # Placeholder for stream handling
                 content = "Streaming response..."
            else:
                 content = response.choices[0].message.content

            import json
            # Attempt to parse JSON from the response
            try:
                # Cleanup potential markdown ticks if model adds them
                clean_content = content.replace("```json", "").replace("```", "")
                return json.loads(clean_content)
            except json.JSONDecodeError:
                return {"summary": content, "justification": "", "recommended_action": ""}
                
        except Exception as e:
            return {"error": str(e), "summary": "LLM Error"}
