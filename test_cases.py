import requests
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI, AzureOpenAI
import streamlit as st

from google import genai as google_genai
from groq import Groq
from zhipuai import ZhipuAI
from utils import process_groq_response, create_reasoning_system_prompt
from i18n import get_prompt_language_suffix

# Function to create a prompt to generate mitigating controls
def create_test_cases_prompt(threats, language="en"):
    language_suffix = get_prompt_language_suffix(language)

    if language == "zh":
        prompt = f"""
作为一名拥有超过20年STRIDE威胁建模方法经验的网络安全专家，您的任务是为威胁模型中识别的威胁提供Gherkin测试用例。您的响应必须根据威胁的详细信息进行调整。

以下是识别出的威胁列表：
{threats}

在'Given'步骤中使用威胁描述，使测试用例特定于识别的威胁。
将Gherkin语法放在三重反引号（```）内，以在Markdown中格式化测试用例。为每个测试用例添加标题。
例如：

    ```gherkin
    Given 一个拥有有效账户的用户
    When 用户登录
    Then 用户应该能够访问系统
    ```

您的响应（不要添加介绍性文本，只提供Gherkin测试用例）：
{language_suffix}
"""
    else:
        prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology.
Your task is to provide Gherkin test cases for the threats identified in a threat model. It is very important that
your responses are tailored to reflect the details of the threats.

Below is the list of identified threats:
{threats}

Use the threat descriptions in the 'Given' steps so that the test cases are specific to the threats identified.
Put the Gherkin syntax inside triple backticks (```) to format the test cases in Markdown. Add a title for each test case.
For example:

    ```gherkin
    Given a user with a valid account
    When the user logs in
    Then the user should be able to access the system
    ```

YOUR RESPONSE (do not add introductory text, just provide the Gherkin test cases):
{language_suffix}
"""
    return prompt


# Function to get test cases from the GPT response.
def get_test_cases(api_key, model_name, prompt, language="en"):
    client = OpenAI(api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini), use a structured system prompt
    if model_name in ["o1", "o3", "o3-mini", "o4-mini"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Generate comprehensive security test cases in Gherkin format for the identified threats.",
            approach_description="""1. Analyze each threat in the provided threat model:
   - Understand the threat type and scenario
   - Identify critical security aspects to test
   - Consider both positive and negative test cases
2. For each test case:
   - Write clear preconditions in 'Given' steps
   - Define specific actions in 'When' steps
   - Specify expected outcomes in 'Then' steps
   - Include relevant security validation checks
3. Structure the test cases:
   - Add descriptive titles for each scenario
   - Use proper Gherkin syntax and formatting
   - Group related test cases together
   - Include edge cases and boundary conditions
4. Format output as Markdown with Gherkin code blocks:
   - Use proper code block syntax
   - Ensure consistent indentation
   - Add clear scenario descriptions"""
        )
        # Create completion with max_completion_tokens for reasoning models
        response = client.chat.completions.create(
            model = model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_completion_tokens=4000
        )
    else:
        system_prompt = "You are a helpful assistant that provides Gherkin test cases in Markdown format."
        # Create completion with max_tokens for other models
        response = client.chat.completions.create(
            model = model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000
        )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get mitigations from the Azure OpenAI response.
def get_test_cases_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt, language="en"):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get test cases from the Google model's response.
def get_test_cases_google(google_api_key, google_model, prompt, language="en"):
    client = google_genai.Client(api_key=google_api_key)
    
    safety_settings = [
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        )
    ]
    
    system_instruction = "You are a helpful assistant that provides Gherkin test cases in Markdown format."
    is_gemini_2_5 = "gemini-2.5" in google_model.lower()
    
    try:
        from google.genai import types as google_types
        if is_gemini_2_5:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=safety_settings,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024)
            )
        else:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=safety_settings
            )
        response = client.models.generate_content(
            model=google_model,
            contents=prompt,
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
        st.error(f"Error generating test cases with Google AI: {str(e)}")
        return f"""
## Error Generating Test Cases

**API Error:** {str(e)}

Please try again or select a different model provider.
"""
    
    test_cases = response.text
    return test_cases

# Function to get test cases from the Mistral model's response.
def get_test_cases_mistral(mistral_api_key, mistral_model, prompt, language="en"):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model = mistral_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get test cases from Ollama hosted LLM.
def get_test_cases_ollama(ollama_endpoint, ollama_model, prompt, language="en"):
    """
    Get test cases from Ollama hosted LLM.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model
        
    Returns:
        str: The generated test cases in markdown format
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        KeyError: If the response doesn't contain the expected fields
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system", 
                "content": """You are a cyber security expert with more than 20 years experience of security testing applications. Your task is to analyze the provided application description and suggest appropriate security test cases.

Please provide your response in markdown format with appropriate headings and bullet points. For each test case, include:
- Test objective
- Prerequisites
- Test steps
- Expected results
- Pass/fail criteria"""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()
        
        try:
            # Access the 'content' attribute of the 'message' dictionary
            test_cases = outer_json["message"]["content"]
            return test_cases
            
        except KeyError as e:
            # Handle error without printing debug info
            raise
            
    except requests.exceptions.RequestException as e:
        # Handle error without printing debug info
        raise

# Function to get test cases from the Anthropic model's response.
def get_test_cases_anthropic(anthropic_api_key, anthropic_model, prompt, language="en"):
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
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
                system="You are a helpful assistant that provides Gherkin test cases in Markdown format.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=600  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a helpful assistant that provides Gherkin test cases in Markdown format.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=300  # 5-minute timeout
            )

        # Access the text content
        if is_thinking_mode:
            # For thinking mode, we need to extract only the text content blocks
            test_cases = ''.join(block.text for block in response.content if block.type == "text")
            
            # Store thinking content in session state for debugging/transparency (optional)
            thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
            if thinking_content:
                st.session_state['last_thinking_content'] = thinking_content
        else:
            # Standard handling for regular responses
            test_cases = response.content[0].text

        return test_cases
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        
        # Create a fallback response for timeout or other errors
        fallback_test_cases = f"""
## Error Generating Test Cases

**API Error:** {error_message}

### Suggestions:
- For complex applications, try simplifying the input or breaking it into smaller components
- If you're using extended thinking mode and encountering timeouts, try the standard model instead
- Consider reducing the complexity of the application description
"""
        return fallback_test_cases

# Function to get test cases from LM Studio Server response.
def get_test_cases_lm_studio(lm_studio_endpoint, model_name, prompt, language="en"):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    test_cases = response.choices[0].message.content

    return test_cases

# Function to get test cases from the Groq model's response.
def get_test_cases_groq(groq_api_key, groq_model, prompt, language="en"):
    client = Groq(api_key=groq_api_key)
    response = client.chat.completions.create(
        model=groq_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Process the response using our utility function
    reasoning, test_cases = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=False
    )
    
    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return test_cases

# Function to get test cases from GLM response
def get_test_cases_glm(glm_api_key, glm_model, prompt, language="en"):
    """
    Get test cases from GLM (Zhipu AI) response.

    Args:
        glm_api_key (str): The GLM API key
        glm_model (str): The GLM model name
        prompt (str): The prompt to send to the model

    Returns:
        str: Markdown formatted test cases
    """
    client = OpenAI(
    api_key= glm_api_key,
    base_url="https://open.bigmodel.cn/api/paas/v4/"
    )

    try:
        response = client.chat.completions.create(
            model=glm_model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert with extensive experience in security testing and threat modeling. Generate detailed Gherkin test cases for security testing."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )

        return response.choices[0].message.content

    except Exception as e:
        st.error(f"Error generating test cases with GLM: {str(e)}")
        return "Error generating test cases. Please check your API key and try again."

# Function to get test cases from eCloud response
def get_test_cases_ecloud(ecloud_api_key, ecloud_model, prompt, language="en"):
    """
    Get test cases from eCloud response.

    Args:
        ecloud_api_key (str): The eCloud API key
        ecloud_model (str): The eCloud model name
        prompt (str): The prompt to send to the model

    Returns:
        str: Markdown formatted test cases
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
            {"role": "system", "content": "You are a cybersecurity expert with extensive experience in security testing and threat modeling. Generate detailed Gherkin test cases for security testing."},
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
        return result['choices'][0]['message']['content']

    except requests.exceptions.RequestException as e:
        st.error(f"Error generating test cases with eCloud: {str(e)}")
        return "Error generating test cases. Please check your API key and try again."
    except Exception as e:
        st.error(f"Unexpected error with eCloud: {str(e)}")
        return "Error generating test cases. An unexpected error occurred."