import json
import requests
import base64
from anthropic import Anthropic
from mistralai import Mistral, UserMessage
from openai import OpenAI, AzureOpenAI
import streamlit as st
import re

from google import genai as google_genai
from groq import Groq
from zhipuai import ZhipuAI
from utils import process_groq_response, create_reasoning_system_prompt
from i18n import get_prompt_language_suffix

# Function to convert JSON to Markdown for display.
def json_to_markdown(threat_model, improvement_suggestions):
    markdown_output = "## Threat Model\n\n"

    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"

    # Fill the table rows with the threat model data
    for threat in threat_model:
        # Handle different field name variations that models might return
        threat_type = threat.get('Threat Type') or threat.get('threat_type') or threat.get('threatType') or threat.get('type') or 'Unknown'
        scenario = threat.get('Scenario') or threat.get('scenario') or threat.get('description') or 'Unknown scenario'
        potential_impact = threat.get('Potential Impact') or threat.get('potential_impact') or threat.get('impact') or threat.get('effect') or 'Unknown impact'

        markdown_output += f"| {threat_type} | {scenario} | {potential_impact} |\n"

    markdown_output += "\n\n## " + get_text("improvement_suggestions", language) + "\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"

    return markdown_output

# Function to create a prompt for generating a threat model
def create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input, language="en"):
    language_suffix = get_prompt_language_suffix(language)

    if language == "zh":
        prompt = f"""
作为一名拥有超过20年STRIDE威胁建模方法经验的网络安全专家，您的任务是为各种应用程序生成全面的威胁模型。请分析提供的代码摘要、README内容和应用程序描述，为该应用程序生成具体的威胁列表。

请特别注意README内容，因为它通常提供有关项目目的、架构和潜在安全考虑的宝贵上下文。

对于每个STRIDE类别（欺骗、篡改、否认、信息泄露、拒绝服务和权限提升），如果适用，请列出多个（3或4个）可信威胁。每个威胁场景应提供一个在应用程序上下文中可能发生威胁的可信场景。您的响应必须根据给定的详细信息进行调整。

提供威胁模型时，使用JSON格式的响应，键为"threat_model"和"improvement_suggestions"。在"threat_model"下，包含一个对象数组，键为"Threat Type"、"Scenario"和"Potential Impact"。

在"improvement_suggestions"下，包含一个字符串数组，建议用户可以提供哪些额外信息或详细信息，以使威胁模型在下一迭代中更加全面和准确。专注于识别提供的应用程序描述中的空白，如果填补这些空白，将能够进行更详细和精确的威胁分析。例如：
- 缺失架构细节，这将有助于识别更具体的威胁
- 不明确的身份验证流程，需要更多细节
- 不完整的数据流描述
- 缺失技术栈信息
- 不明确的系统边界或信任区域
- 敏感数据处理的描述不完整

不要提供一般的安全建议 - 专注于什么额外信息有助于创建更好的威胁模型。

应用程序类型：{app_type}
身份验证方法：{authentication}
面向互联网：{internet_facing}
敏感数据：{sensitive_data}
代码摘要、README内容和应用程序描述：
{app_input}

预期JSON响应格式示例：

    {{
      "threat_model": [
        {{
          "Threat Type": "欺骗",
          "Scenario": "示例场景1",
          "Potential Impact": "示例潜在影响1"
        }},
        {{
          "Threat Type": "欺骗",
          "Scenario": "示例场景2",
          "Potential Impact": "示例潜在影响2"
        }},
        // ... 更多威胁
      ],
      "improvement_suggestions": [
        "请提供有关组件间身份验证流程的更多详细信息，以更好地分析潜在的身份验证绕过场景。",
        "考虑添加有关敏感数据如何存储和传输的信息，以实现更精确的数据暴露威胁分析。",
        // ... 更多改进威胁模型输入的建议
      ]
    }}
{language_suffix}
"""
    else:
        prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to analyze the provided code summary, README content, and application description to produce a list of specific threats for the application.

Pay special attention to the README content as it often provides valuable context about the project's purpose, architecture, and potential security considerations.

For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list multiple (3 or 4) credible threats if applicable. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

When providing the threat model, use a JSON formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", and "Potential Impact".

Under "improvement_suggestions", include an array of strings that suggest what additional information or details the user could provide to make the threat model more comprehensive and accurate in the next iteration. Focus on identifying gaps in the provided application description that, if filled, would enable a more detailed and precise threat analysis. For example:
- Missing architectural details that would help identify more specific threats
- Unclear authentication flows that need more detail
- Incomplete data flow descriptions
- Missing technical stack information
- Unclear system boundaries or trust zones
- Incomplete description of sensitive data handling

Do not provide general security recommendations - focus only on what additional information would help create a better threat model.

APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
CODE SUMMARY, README CONTENT, AND APPLICATION DESCRIPTION:
{app_input}

Example of expected JSON response format:

    {{
      "threat_model": [
        {{
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario 1",
          "Potential Impact": "Example Potential Impact 1"
        }},
        {{
          "Threat Type": "Spoofing",
          "Scenario": "Example Scenario 2",
          "Potential Impact": "Example Potential Impact 2"
        }},
        // ... more threats
      ],
      "improvement_suggestions": [
        "Please provide more details about the authentication flow between components to better analyze potential authentication bypass scenarios.",
        "Consider adding information about how sensitive data is stored and transmitted to enable more precise data exposure threat analysis.",
        // ... more suggestions for improving the threat model input
      ]
    }}
{language_suffix}
"""
    return prompt

def create_image_analysis_prompt():
    prompt = """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to 
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key 
         components, their interactions, and any technologies used.
    
    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional 
    discussion.
    
    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.
    """
    return prompt

# Function to get analyse uploaded architecture diagrams.
def get_image_analysis(api_key, model_name, prompt, base64_image):
    client = OpenAI(api_key=api_key)

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": prompt
                },
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                }
            ]
        }
    ]
    
    # If using o4-mini, use the structured system prompt approach
    if model_name == "o4-mini":
        system_prompt = create_reasoning_system_prompt(
            task_description="Analyze the provided architecture diagram and explain it to a Security Architect.",
            approach_description="""1. Carefully examine the diagram
2. Identify all components and their relationships
3. Note any technologies, protocols, or security measures shown
4. Create a clear, structured explanation with these sections:
   - Overall Architecture: Brief overview of the system
   - Key Components: List and explain each major component
   - Data Flow: How information moves through the system
   - Technologies Used: Identify technologies, frameworks, or platforms
   - Security Considerations: Note any visible security measures"""
        )
        # Insert system message at the beginning
        messages.insert(0, {"role": "system", "content": system_prompt})
        
        # Create completion with max_completion_tokens for reasoning models
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_completion_tokens=4000
            )
            return {
                "choices": [
                    {"message": {"content": response.choices[0].message.content}}
                ]
            }
        except Exception as e:
            return None
    else:
        # For standard models (gpt-4, etc.)
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_tokens=4000
            )
            return {
                "choices": [
                    {"message": {"content": response.choices[0].message.content}}
                ]
            }
        except Exception as e:
            return None

# Function to get image analysis using Azure OpenAI
def get_image_analysis_azure(api_endpoint, api_key, api_version, deployment_name, prompt, base64_image):
    client = AzureOpenAI(
        azure_endpoint=api_endpoint,
        api_key=api_key,
        api_version=api_version,
    )

    response = client.chat.completions.create(
        model=deployment_name,
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}},
                ],
            }
        ],
        max_tokens=4000,
    )

    return {
        "choices": [
            {"message": {"content": response.choices[0].message.content}}
        ]
    }


# Function to get image analysis using Google Gemini models
def get_image_analysis_google(api_key, model_name, prompt, base64_image):
    client = google_genai.Client(api_key=api_key)
    from google.genai import types as google_types

    blob = google_types.Blob(data=base64.b64decode(base64_image), mime_type="image/jpeg")
    content = [
        google_types.Content(role="user", parts=[
            google_types.Part(text=prompt),
            google_types.Part(inlineData=blob),
        ])
    ]

    config = google_types.GenerateContentConfig()
    response = client.models.generate_content(model=model_name, contents=content, config=config)

    return {"choices": [{"message": {"content": response.text}}]}


# Function to get image analysis using Anthropic Claude models
def get_image_analysis_anthropic(api_key, model_name, prompt, base64_image, media_type="image/jpeg"):
    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model_name,
        max_tokens=4000,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": base64_image,
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }
        ],
    )

    text = "".join(block.text for block in response.content if getattr(block, "text", None))
    return {"choices": [{"message": {"content": text}}]}


# Function to get threat model from the GPT response.
def get_threat_model(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini), use a structured system prompt
    if model_name in ["o1", "o3", "o3-mini", "o4-mini"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Analyze the provided application description and generate a comprehensive threat model using the STRIDE methodology.",
            approach_description="""1. Carefully read and understand the application description
2. For each component and data flow:
   - Identify potential Spoofing threats
   - Identify potential Tampering threats
   - Identify potential Repudiation threats
   - Identify potential Information Disclosure threats
   - Identify potential Denial of Service threats
   - Identify potential Elevation of Privilege threats
3. For each identified threat:
   - Describe the specific scenario
   - Analyze the potential impact
4. Generate improvement suggestions based on identified threats
5. Format the output as a JSON object with 'threat_model' and 'improvement_suggestions' arrays"""
        )
        # Create completion with max_completion_tokens for reasoning models
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_completion_tokens=4000
        )
    else:
        system_prompt = "You are a helpful assistant designed to output JSON."
        # Create completion with max_tokens for other models
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000
        )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content


# Function to get threat model from the Azure OpenAI response.
def get_threat_model_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
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
    response_content = json.loads(response.choices[0].message.content)

    return response_content


# Function to get threat model from the Google response.
def get_threat_model_google(google_api_key, google_model, prompt):
    # Create a client with the Google API key
    client = google_genai.Client(api_key=google_api_key)
    
    # Set up safety settings to allow security content
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
    
    # Check if we're using a Gemini 2.5 model (which supports thinking capabilities)
    is_gemini_2_5 = "gemini-2.5" in google_model.lower()
    
    try:
        from google.genai import types as google_types
        if is_gemini_2_5:
            config = google_types.GenerateContentConfig(
                response_mime_type='application/json',
                safety_settings=safety_settings,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024)
            )
        else:
            config = google_types.GenerateContentConfig(
                response_mime_type='application/json',
                safety_settings=safety_settings
            )
        
        # Generate content using the configured settings
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
        st.error(f"Error generating content with Google AI: {str(e)}")
        return None
    
    try:
        # Parse the response text as JSON
        response_content = json.loads(response.text)
    except json.JSONDecodeError:
        st.error("Failed to parse JSON response from Google AI")
        return None
        
    return response_content

# Function to get threat model from the Mistral response.
def get_threat_model_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model = mistral_model,
        response_format={"type": "json_object"},
        messages=[
            UserMessage(content=prompt)
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content

# Function to get threat model from Ollama hosted LLM.
def get_threat_model_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Get threat model from Ollama hosted LLM.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model
        
    Returns:
        dict: The parsed JSON response from the model
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        json.JSONDecodeError: If the response cannot be parsed as JSON
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/generate"

    system_prompt = "You are a helpful assistant designed to output JSON."
    full_prompt = f"{system_prompt}\n\n{prompt}"

    data = {
        "model": ollama_model,
        "prompt": full_prompt,
        "stream": False,
        "format": "json"
    }

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()
        
        try:
            # Parse the JSON response from the model's response field
            inner_json = json.loads(outer_json['response'])
            return inner_json
        except (json.JSONDecodeError, KeyError):

            raise
            
    except requests.exceptions.RequestException:

        raise

# Function to get threat model from the Claude response.
def get_threat_model_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using Claude 3.7
    is_claude_3_7 = "claude-3-7" in anthropic_model.lower()
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model
    
    try:
        # For Claude 3.7, use a more explicit prompt structure
        if is_claude_3_7:
            # Add explicit JSON formatting instructions to the prompt
            json_prompt = prompt + "\n\nIMPORTANT: Your response MUST be a valid JSON object with the exact structure shown in the example above. Do not include any explanatory text, markdown formatting, or code blocks. Return only the raw JSON object."
            
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
                        {"role": "user", "content": json_prompt}
                    ],
                    timeout=600  # 10-minute timeout
                )
            else:
                response = client.messages.create(
                    model=actual_model,
                    max_tokens=4096,
                    system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                    messages=[
                        {"role": "user", "content": json_prompt}
                    ],
                    timeout=300  # 5-minute timeout
                )
        else:
            # Standard handling for other Claude models
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a helpful assistant designed to output JSON. Your response must be a valid, parseable JSON object with no additional text, markdown formatting, or explanation. Do not include ```json code blocks or any other formatting - just return the raw JSON object.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=300  # 5-minute timeout
            )
        
        # Combine all text blocks into a single string
        if is_thinking_mode:
            # For thinking mode, we need to extract only the text content blocks
            full_content = ''.join(block.text for block in response.content if block.type == "text")
            
            # Store thinking content in session state for debugging/transparency (optional)
            thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
            if thinking_content:
                st.session_state['last_thinking_content'] = thinking_content
        else:
            # Standard handling for regular responses
            full_content = ''.join(block.text for block in response.content)
        
        # Parse the JSON response
        try:
            # Check for and fix common JSON formatting issues
            if is_claude_3_7:
                # Sometimes Claude 3.7 adds trailing commas which are invalid in JSON
                full_content = full_content.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
                
                # Sometimes it adds comments which are invalid in JSON
                full_content = re.sub(r'//.*?\n', '\n', full_content)
            
            response_content = json.loads(full_content)
            return response_content
        except json.JSONDecodeError as e:
            # Create a fallback response
            fallback_response = {
                "threat_model": [
                    {
                        "Threat Type": "Error",
                        "Scenario": "Failed to parse Claude response",
                        "Potential Impact": "Unable to generate threat model"
                    }
                ],
                "improvement_suggestions": [
                    "Try again - sometimes the model returns a properly formatted response on subsequent attempts",
                    "Check the logs for detailed error information"
                ]
            }
            return fallback_response
            
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        
        # Create a fallback response for timeout or other errors
        fallback_response = {
            "threat_model": [
                {
                    "Threat Type": "Error",
                    "Scenario": f"API Error: {error_message}",
                    "Potential Impact": "Unable to generate threat model"
                }
            ],
            "improvement_suggestions": [
                "For complex applications, try simplifying the input or breaking it into smaller components",
                "If you're using extended thinking mode and encountering timeouts, try the standard model instead",
                "Consider reducing the complexity of the application description"
            ]
        }
        return fallback_response

# Function to get threat model from LM Studio Server response.
def get_threat_model_lm_studio(lm_studio_endpoint, model_name, prompt):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    # Define the expected response structure
    threat_model_schema = {
        "type": "json_schema",
        "json_schema": {
            "name": "threat_model_response",
            "schema": {
                "type": "object",
                "properties": {
                    "threat_model": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "Threat Type": {"type": "string"},
                                "Scenario": {"type": "string"},
                                "Potential Impact": {"type": "string"}
                            },
                            "required": ["Threat Type", "Scenario", "Potential Impact"]
                        }
                    },
                    "improvement_suggestions": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                "required": ["threat_model", "improvement_suggestions"]
            }
        }
    }

    response = client.chat.completions.create(
        model=model_name,
        response_format=threat_model_schema,
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content

# Function to get threat model from the Groq response.
def get_threat_model_groq(groq_api_key, groq_model, prompt):
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
    reasoning, response_content = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=True
    )
    
    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return response_content

# Function to get threat model from GLM response.
def get_threat_model_glm(glm_api_key, glm_model, prompt):
    """
    Get threat model from GLM (Zhipu AI) response.

    Args:
        glm_api_key (str): The GLM API key
        glm_model (str): The GLM model name (e.g., 'glm-4.5', 'glm-4.5-air')
        prompt (str): The prompt to send to the model

    Returns:
        dict: The parsed JSON response from the model
    """
    client = OpenAI(
    api_key= glm_api_key,
    base_url="https://open.bigmodel.cn/api/paas/v4/"
    )
    

    try:
        response = client.chat.completions.create(
            model=glm_model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant designed to output JSON. Your response must be a valid, parseable JSON object with no additional text, markdown formatting, or explanation."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000,
            response_format={"type": "json_object"}
        )

        # Parse the JSON response
        response_content = json.loads(response.choices[0].message.content)
        return response_content

    except json.JSONDecodeError as e:
        # Handle JSON parsing errors
        st.error(f"Failed to parse JSON response from GLM: {str(e)}")

        # Create a fallback response
        fallback_response = {
            "threat_model": [
                {
                    "Threat Type": "Error",
                    "Scenario": "Failed to parse GLM response",
                    "Potential Impact": "Unable to generate threat model"
                }
            ],
            "improvement_suggestions": [
                "Try again - sometimes the model returns a properly formatted response on subsequent attempts",
                "Check if the model supports JSON output format",
                "Consider simplifying the input prompt"
            ]
        }
        return fallback_response

    except Exception as e:
        # Handle API errors
        error_message = str(e)
        st.error(f"Error with GLM API: {error_message}")

        # Create a fallback response for API errors
        fallback_response = {
            "threat_model": [
                {
                    "Threat Type": "Error",
                    "Scenario": f"API Error: {error_message}",
                    "Potential Impact": "Unable to generate threat model"
                }
            ],
            "improvement_suggestions": [
                "Check your API key and model name",
                "Verify the GLM API service is available",
                "Consider using a different model if the issue persists"
            ]
        }
        return fallback_response

# Function to get image analysis using GLM models
def get_image_analysis_glm(glm_api_key, glm_model, prompt, base64_image, media_type="image/jpeg"):
    """
    Get image analysis using GLM (Zhipu AI) models.

    Args:
        glm_api_key (str): The GLM API key
        glm_model (str): The GLM model name
        prompt (str): The prompt for image analysis
        base64_image (str): Base64 encoded image data
        media_type (str): Media type of the image (default: "image/jpeg")

    Returns:
        dict: Response with the analysis content
    """
    client = OpenAI(
    api_key= glm_api_key,
    base_url="https://open.bigmodel.cn/api/paas/v4/"
    )

    try:
        # Prepare the message with image
        response = client.chat.completions.create(
            model=glm_model,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:{media_type};base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            max_tokens=4000
        )

        return {
            "choices": [
                {"message": {"content": response.choices[0].message.content}}
            ]
        }

    except Exception as e:
        error_message = str(e)
        st.error(f"Error with GLM image analysis: {error_message}")
        return None