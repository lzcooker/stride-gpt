import json
import requests
import time
import re
from anthropic import Anthropic
from mistralai import Mistral, UserMessage
from openai import OpenAI, AzureOpenAI
import streamlit as st

from google import genai as google_genai
from groq import Groq
from zhipuai import ZhipuAI
from utils import process_groq_response, create_reasoning_system_prompt
from i18n import get_prompt_language_suffix, get_text

def dread_json_to_markdown(dread_assessment, language="en"):
    # Create a clean Markdown table with proper spacing using i18n
    markdown_output = f"| Threat Type | Scenario | {get_text('dread_damage_potential', language)} | {get_text('dread_reproducibility', language)} | {get_text('dread_exploitability', language)} | {get_text('dread_affected_users', language)} | {get_text('dread_discoverability', language)} | Risk Score |\n"
    markdown_output += "|------------|----------|------------------|-----------------|----------------|----------------|-----------------|------------|\n"
    
    try:
        # Access the list of threats under the "Risk Assessment" key
        threats = dread_assessment.get("Risk Assessment", [])
        
        # If there are no threats, add a message row
        if not threats:
            markdown_output += "| No threats found | Please generate a threat model first | - | - | - | - | - | - |\n"
            return markdown_output
            
        for threat in threats:
            # Check if threat is a dictionary
            if isinstance(threat, dict):
                # Get values with defaults
                threat_type = threat.get('Threat Type', 'N/A')
                scenario = threat.get('Scenario', 'N/A')
                damage_potential = threat.get('Damage Potential', 0)
                reproducibility = threat.get('Reproducibility', 0)
                exploitability = threat.get('Exploitability', 0)
                affected_users = threat.get('Affected Users', 0)
                discoverability = threat.get('Discoverability', 0)
                
                # Calculate the Risk Score
                risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5
                
                # Escape any pipe characters in text fields to prevent table formatting issues
                threat_type = str(threat_type).replace('|', '\\|')
                scenario = str(scenario).replace('|', '\\|')
                
                # Ensure scenario text doesn't break table formatting by limiting length and removing newlines
                if len(scenario) > 100:
                    scenario = scenario[:97] + "..."
                scenario = scenario.replace('\n', ' ').replace('\r', '')
                
                # Add the row to the table with proper formatting
                markdown_output += f"| {threat_type} | {scenario} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                # Skip non-dictionary entries and log a warning
                markdown_output += "| Invalid threat | Threat data is not in the correct format | - | - | - | - | - | - |\n"
    except Exception as e:
        # Add a note about the error and a placeholder row
        markdown_output += "| Error | An error occurred while processing the DREAD assessment | - | - | - | - | - | - |\n"
    
    # Add a blank line after the table for better rendering
    markdown_output += "\n"
    return markdown_output


# Function to create a prompt to generate mitigating controls
def create_dread_assessment_prompt(threats, language="en"):
    language_suffix = get_prompt_language_suffix(language)

    if language == "zh":
        prompt = f"""
作为一名拥有超过20年STRIDE和DREAD威胁建模方法经验的网络安全专家，您的任务是为威胁模型中识别的威胁生成DREAD风险评估。

以下是识别出的威胁列表：
{threats}
提供风险评估时，使用JSON格式的响应，顶层键为"Risk Assessment"，威胁列表中的每个威胁都有以下子键：
- "Threat Type": 表示威胁类型的字符串（例如，"欺骗"）。
- "Scenario": 描述威胁场景的字符串。
- "Damage Potential": 1到10之间的整数。
- "Reproducibility": 1到10之间的整数。
- "Exploitability": 1到10之间的整数。
- "Affected Users": 1到10之间的整数。
- "Discoverability": 1到10之间的整数。
根据DREAD方法为每个子键分配1到10之间的值。使用以下比例：
- 1-3：低
- 4-6：中
- 7-10：高
确保JSON响应格式正确，不包含任何额外文本。以下是预期的JSON响应格式示例：
{{
  "Risk Assessment": [
    {{
      "Threat Type": "欺骗",
      "Scenario": "攻击者可以创建虚假的OAuth2提供者并诱骗用户通过它登录。",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }},
    {{
      "Threat Type": "欺骗",
      "Scenario": "攻击者可以通过中间人（MitM）攻击拦截OAuth2令牌交换过程。",
      "Damage Potential": 8,
      "Reproducibility": 7,
      "Exploitability": 6,
      "Affected Users": 8,
      "Discoverability": 6
    }}
  ]
}}
{language_suffix}
"""
    else:
        prompt = f"""
Act as a cyber security expert with more than 20 years of experience in threat modeling using STRIDE and DREAD methodologies.
Your task is to produce a DREAD risk assessment for the threats identified in a threat model.
Below is the list of identified threats:
{threats}
When providing the risk assessment, use a JSON formatted response with a top-level key "Risk Assessment" and a list of threats, each with the following sub-keys:
- "Threat Type": A string representing the type of threat (e.g., "Spoofing").
- "Scenario": A string describing the threat scenario.
- "Damage Potential": An integer between 1 and 10.
- "Reproducibility": An integer between 1 and 10.
- "Exploitability": An integer between 1 and 10.
- "Affected Users": An integer between 1 and 10.
- "Discoverability": An integer between 1 and 10.
Assign a value between 1 and 10 for each sub-key based on the DREAD methodology. Use the following scale:
- 1-3: Low
- 4-6: Medium
- 7-10: High
Ensure the JSON response is correctly formatted and does not contain any additional text. Here is an example of the expected JSON response format:
{{
  "Risk Assessment": [
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could create a fake OAuth2 provider and trick users into logging in through it.",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }},
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could intercept the OAuth2 token exchange process through a Man-in-the-Middle (MitM) attack.",
      "Damage Potential": 8,
      "Reproducibility": 7,
      "Exploitability": 6,
      "Affected Users": 8,
      "Discoverability": 6
    }}
  ]
}}
{language_suffix}
"""
    return prompt

def clean_json_response(response_text):
    import re
    # Remove markdown JSON code block if present
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no JSON code block, try to find content between any code blocks
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no code blocks, return the original text
    return response_text.strip()

def get_dread_assessment(api_key, model_name, prompt, language="en"):
    client = OpenAI(api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini), use a structured system prompt
    if model_name in ["o1", "o3", "o3-mini", "o4-mini"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Perform a DREAD risk assessment for the identified security threats.",
            approach_description="""1. For each threat in the provided threat model:
   - Analyze the threat type and scenario in detail
   - Evaluate Damage Potential (1-10):
     * Consider direct and indirect damage
     * Assess financial, reputational, and operational impact
   - Evaluate Reproducibility (1-10):
     * Assess how reliably the attack can be reproduced
     * Consider required conditions and resources
   - Evaluate Exploitability (1-10):
     * Analyze technical complexity
     * Consider required skills and tools
   - Evaluate Affected Users (1-10):
     * Determine scope of impact
     * Consider both direct and indirect users
   - Evaluate Discoverability (1-10):
     * Assess how easily the vulnerability can be found
     * Consider visibility and detection methods
2. Format output as JSON with 'Risk Assessment' array containing:
   - Threat Type
   - Scenario
   - Numerical scores (1-10) for each DREAD category"""
        )
    else:
        system_prompt = "You are a helpful assistant designed to output JSON."

    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )
    
    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        # Handle error silently
        dread_assessment = {}
    
    return dread_assessment

def get_dread_assessment_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt, language="en"):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        # Handle error silently
        dread_assessment = {}
    
    return dread_assessment

# Function to get DREAD risk assessment from the Google model's response.
def get_dread_assessment_google(google_api_key, google_model, prompt, language="en"):
    """
    Generate a DREAD risk assessment using the Gemini API (Google AI) as per official documentation:
    https://ai.google.dev/gemini-api/docs/text-generation
    """
    client = google_genai.Client(api_key=google_api_key)
    system_instruction = (
        "You are a helpful assistant designed to output JSON. "
        "Only provide the DREAD risk assessment in JSON format with no additional text. "
        "Do not wrap the output in a code block."
    )

    is_gemini_2_5 = "gemini-2.5" in google_model.lower()

    try:
        from google.genai import types as google_types
        if is_gemini_2_5:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024)
            )
        else:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction
            )
        response = client.models.generate_content(
            model=google_model,
            contents=[prompt],
            config=config
        )
        # Extract Gemini 2.5 'thinking' content if present
        thinking_content = []
        for candidate in getattr(response, 'candidates', []):
            content = getattr(candidate, 'content', None)
            if content and hasattr(content, 'parts'):
                for part in content.parts:
                    if hasattr(part, 'thought') and part.thought:
                        thinking_content.append(str(part.thought))
        if thinking_content:
            joined_thinking = "\n\n".join(thinking_content)
            st.session_state['last_thinking_content'] = joined_thinking
    except Exception as e:
        st.error(f"Error generating DREAD assessment with Google AI: {str(e)}")
        return {"Risk Assessment": []}

    cleaned = clean_json_response(response.text)

    try:
        dread_assessment = json.loads(cleaned)
        return dread_assessment
    except json.JSONDecodeError:
        return {}

# Function to get DREAD risk assessment from the Mistral model's response.
def get_dread_assessment_mistral(mistral_api_key, mistral_model, prompt, language="en"):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model=mistral_model,
        response_format={"type": "json_object"},
        messages=[
            UserMessage(content=prompt)
        ]
    )

    try:
        # Convert the JSON string in the 'content' field to a Python dictionary
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        dread_assessment = {}

    return dread_assessment

# Function to get DREAD risk assessment from Ollama hosted LLM.
def get_dread_assessment_ollama(ollama_endpoint, ollama_model, prompt, language="en"):
    """
    Get DREAD risk assessment from Ollama hosted LLM.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model
        
    Returns:
        dict: The parsed JSON response containing the DREAD assessment
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        json.JSONDecodeError: If the response cannot be parsed as JSON
        KeyError: If the response doesn't contain the expected fields
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/chat"

    max_retries = 3
    retry_delay = 2 # seconds

    data = {
        "model": ollama_model,
        "stream": False,
        "format": "json",
        "messages": [
            {
                "role": "system", 
                "content": """You are a cyber security expert with more than 20 years experience of using the DREAD risk assessment methodology to evaluate security threats. Your task is to analyze the provided application description and perform a DREAD assessment.

Please provide your response in JSON format with the following structure:
{
    "dread_assessment": [
        {
            "threat": "Description of the threat",
            "damage": "Score and explanation",
            "reproducibility": "Score and explanation",
            "exploitability": "Score and explanation",
            "affected_users": "Score and explanation",
            "discoverability": "Score and explanation",
            "risk_score": "Calculated total score"
        }
    ]
}"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=data, timeout=60)  # Add timeout
            response.raise_for_status()  # Raise exception for bad status codes
            outer_json = response.json()
            
            try:
                # Access the 'content' attribute of the 'message' dictionary and parse as JSON
                dread_assessment = json.loads(outer_json["message"]["content"])
                return dread_assessment
                
            except (json.JSONDecodeError, KeyError):
                if attempt == max_retries - 1:  # Last attempt
                    raise
                time.sleep(retry_delay)
                continue
                
        except requests.exceptions.RequestException:
            if attempt == max_retries - 1:  # Last attempt
                raise
            time.sleep(retry_delay)
            continue

# Function to get DREAD risk assessment from the Anthropic model's response.
def get_dread_assessment_anthropic(anthropic_api_key, anthropic_model, prompt, language="en"):
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
    # Check if we're using Claude 3.7
    is_claude_3_7 = "claude-3-7" in anthropic_model.lower()
    
    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model
    
    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=24000,
                thinking={
                    "type": "enabled",
                    "budget_tokens": 16000
                },
                system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                messages=[
                    {"role": "user", "content": prompt + "\n\nIMPORTANT: Your response MUST be a valid JSON object with the exact structure shown in the example above. Do not include any explanatory text, markdown formatting, or code blocks. Return only the raw JSON object."}
                ],
                timeout=600  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=300  # 5-minute timeout
            )
        
        try:
            # Extract the text content
            if is_thinking_mode:
                # For thinking mode, we need to extract only the text content blocks
                response_text = ''.join(block.text for block in response.content if block.type == "text")
                
                # Store thinking content in session state for debugging/transparency (optional)
                thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
                if thinking_content:
                    st.session_state['last_thinking_content'] = thinking_content
            else:
                # Standard handling for regular responses
                response_text = response.content[0].text
            
            # Check for and fix common JSON formatting issues
            if is_claude_3_7:
                # Sometimes Claude 3.7 adds trailing commas which are invalid in JSON
                response_text = response_text.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
                
                # Sometimes it adds comments which are invalid in JSON
                response_text = re.sub(r'//.*?\n', '\n', response_text)
            
            # Check if the JSON is complete (should end with a closing brace)
            if not response_text.strip().endswith('}'):
                raise json.JSONDecodeError("Incomplete JSON response", response_text, len(response_text))
                
            # Parse the JSON string
            dread_assessment = json.loads(response_text)
            return dread_assessment
        except (json.JSONDecodeError, IndexError, AttributeError) as e:
            # Create a fallback response with a proper DREAD structure
            fallback_assessment = {
                "Risk Assessment": [
                    {
                        "Threat Type": "Error",
                        "Scenario": f"Failed to parse Claude response: {str(e)}",
                        "Damage Potential": 0,
                        "Reproducibility": 0,
                        "Exploitability": 0,
                        "Affected Users": 0,
                        "Discoverability": 0
                    }
                ]
            }
            return fallback_assessment
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        
        # Create a fallback response for timeout or other errors
        fallback_assessment = {
            "Risk Assessment": [
                {
                    "Threat Type": "Error",
                    "Scenario": f"API Error: {error_message}",
                    "Damage Potential": 0,
                    "Reproducibility": 0,
                    "Exploitability": 0,
                    "Affected Users": 0,
                    "Discoverability": 0
                }
            ]
        }
        return fallback_assessment

# Function to get DREAD risk assessment from LM Studio Server response.
def get_dread_assessment_lm_studio(lm_studio_endpoint, model_name, prompt, language="en"):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    # Define the expected response structure
    dread_schema = {
        "type": "json_schema",
        "json_schema": {
            "name": "dread_assessment_response",
            "schema": {
                "type": "object",
                "properties": {
                    "Risk Assessment": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "Threat Type": {"type": "string"},
                                "Scenario": {"type": "string"},
                                "Damage Potential": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Reproducibility": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Exploitability": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Affected Users": {"type": "integer", "minimum": 1, "maximum": 10},
                                "Discoverability": {"type": "integer", "minimum": 1, "maximum": 10}
                            },
                            "required": ["Threat Type", "Scenario", "Damage Potential", "Reproducibility", "Exploitability", "Affected Users", "Discoverability"]
                        }
                    }
                },
                "required": ["Risk Assessment"]
            }
        }
    }

    response = client.chat.completions.create(
        model=model_name,
        response_format=dread_schema,
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        # Handle error silently
        dread_assessment = {}
    
    return dread_assessment

# Function to get DREAD risk assessment from the Groq model's response.
def get_dread_assessment_groq(groq_api_key, groq_model, prompt, language="en"):
    client = Groq(api_key=groq_api_key)
    response = client.chat.completions.create(
        model=groq_model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ]
    )

    # Process the response using our utility function
    reasoning, dread_assessment = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=True
    )
    
    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return dread_assessment

# Function to get DREAD assessment from GLM response
def get_dread_assessment_glm(glm_api_key, glm_model, prompt, language="en"):
    """
    Get DREAD assessment from GLM (Zhipu AI) response.

    Args:
        glm_api_key (str): The GLM API key
        glm_model (str): The GLM model name
        prompt (str): The prompt to send to the model

    Returns:
        dict: DREAD assessment data
    """
    client = OpenAI(
    api_key= glm_api_key,
    base_url="https://open.bigmodel.cn/api/paas/v4/"
    )

    try:
        response = client.chat.completions.create(
            model=glm_model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in risk assessment. Generate a DREAD risk assessment in valid JSON format."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000,
            response_format={"type": "json_object"}
        )

        # Parse the JSON response
        dread_assessment = json.loads(response.choices[0].message.content)
        return dread_assessment

    except json.JSONDecodeError:
        # Handle JSON parsing errors
        st.error("Failed to parse JSON response from GLM")
        return {"Risk Assessment": []}

    except Exception as e:
        st.error(f"Error generating DREAD assessment with GLM: {str(e)}")
        return {"Risk Assessment": []}

# Function to get DREAD assessment from eCloud response
def get_dread_assessment_ecloud(ecloud_api_key, ecloud_model, prompt, language="en"):
    """
    Get DREAD assessment from eCloud response.

    Args:
        ecloud_api_key (str): The eCloud API key
        ecloud_model (str): The eCloud model name
        prompt (str): The prompt to send to the model

    Returns:
        dict: DREAD assessment data
    """
    import requests

    url = "https://zhenze-huhehaote.cmecloud.cn/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {ecloud_api_key}",
        "Content-Type": "application/json"
    }

    data = {
        "model": ecloud_model,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert specializing in risk assessment. Generate a DREAD risk assessment in valid JSON format."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 4000,
        "stream": False,
        "chat_template_kwargs": {
            "enable_thinking": False
        }
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)
        response.raise_for_status()

        result = response.json()

        # Parse the JSON response
        dread_assessment = json.loads(result['choices'][0]['message']['content'])
        return dread_assessment

    except (json.JSONDecodeError, KeyError) as e:
        # Handle JSON parsing errors
        st.error(f"Failed to parse JSON response from eCloud: {str(e)}")
        return {"Risk Assessment": []}

    except requests.exceptions.RequestException as e:
        st.error(f"Error generating DREAD assessment with eCloud: {str(e)}")
        return {"Risk Assessment": []}
    except Exception as e:
        st.error(f"Unexpected error with eCloud: {str(e)}")
        return {"Risk Assessment": []}