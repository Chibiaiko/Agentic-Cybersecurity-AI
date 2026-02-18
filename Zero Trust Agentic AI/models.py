# models.py
try:
    from openai import OpenAI
except ImportError:
    print("Error: 'openai' module not found. Please run 'pip install openai'")
    raise

from secrets_ import API_KEY
from utils import print_blue


class AIModel:
    def __init__(self, model_name="gpt-5-nano"):
        if not API_KEY or "YOUR_" in API_KEY:
            raise ValueError("Invalid API_KEY in secrets_.py. Please update it.")

        self.client = OpenAI(api_key=API_KEY)
        self.model_name = model_name

    def query(self, system_prompt, user_prompt):
        instruction_part = (
            user_prompt.split("Instruction:")[-1].strip()
            if "Instruction:" in user_prompt
            else user_prompt
        )

        print_blue("\n--- AGENT INSTRUCTION ---")
        print_blue(instruction_part)
        print_blue("------------------------\n")

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI Query Error: {str(e)}"
