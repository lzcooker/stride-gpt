"""
Internationalization (i18n) module for STRIDE GPT
Supports English and Chinese language switching
"""

class translations:
    """Translation strings for English and Chinese"""

    EN = {
        # Main UI
        "app_title": "STRIDE GPT",
        "sidebar_header": "How to use STRIDE GPT",
        "model_provider_label": "Select your preferred model provider:",
        "model_provider_help": "Select the model provider you would like to use. This will determine the models available for selection.",

        # OpenAI Section
        "openai_instructions": """
1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) and chosen model below 🔑
2. Provide details of the application that you would like to threat model  📝
3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
""",
        "openai_api_key_label": "Enter your OpenAI API key:",
        "openai_api_key_help": "You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
        "openai_model_label": "Select the model you would like to use:",
        "openai_model_help": "GPT-4.1 is OpenAI's most advanced model with 1M token context. o1, o3, o3-mini, and o4-mini are reasoning models that perform complex reasoning before responding. o3 and o4-mini are newer models with superior reasoning capabilities and 200K token contexts.",

        # GLM Section
        "glm_instructions": """
1. Enter your [GLM API key](https://open.bigmodel.cn/) and chosen model below 🔑
2. Provide details of the application that you would like to threat model  📝
3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
""",
        "glm_api_key_label": "Enter your GLM API key:",
        "glm_api_key_help": "You can find your GLM API key on the [BigModel console](https://open.bigmodel.cn/).",
        "glm_model_label": "Select the GLM model you would like to use:",
        "glm_model_help": "GLM-4.5 is the latest model with strong reasoning capabilities. GLM-4.5-air is optimized for speed.",

        # Anthropic Section
        "anthropic_instructions": """
1. Enter your [Anthropic API key](https://console.anthropic.com/settings/keys) and chosen model below 🔑
2. Provide details of the application that you would like to threat model  📝
3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀
""",
        "anthropic_api_key_label": "Enter your Anthropic API key:",
        "anthropic_api_key_help": "You can find your Anthropic API key on the [Anthropic console](https://console.anthropic.com/settings/keys).",
        "anthropic_model_label": "Select the Anthropic model you would like to use:",

        # Main App Section
        "app_description_header": "Application Description",
        "app_description_help": "Enter the details of the application that you would like to threat model.",
        "app_type_label": "What type of application are you threat modeling?",
        "app_type_help": "Select the type of application that you are threat modeling.",
        "auth_label": "Does the application have authentication?",
        "auth_help": "Indicate whether the application has any form of authentication.",
        "internet_facing_label": "Is the application internet-facing?",
        "internet_facing_help": "Indicate whether the application is accessible from the internet.",
        "sensitive_data_label": "Does the application handle sensitive data?",
        "sensitive_data_help": "Indicate whether the application handles sensitive data such as PII, financial information, or health records.",
        "app_input_label": "Please provide a description of the application including its architecture, technologies used, and main functionality:",
        "app_input_help": "Provide as much detail as possible about the application including its architecture, technologies used, and main functionality. You can also include code snippets or links to documentation.",
        "analyze_button": "Analyze Application",

        # Threat Model Section
        "threat_model_header": "Threat Model",
        "threat_model_code": "Threat Model Code:",
        "download_threat_model": "Download Threat Model",
        "attack_tree_header": "Attack Tree",
        "attack_tree_code": "Attack Tree Code:",
        "download_attack_tree": "Download Attack Tree Code",
        "open_mermaid_live": "Open Mermaid Live",
        "mitigations_header": "Mitigations",
        "mitigations_code": "Mitigations Code:",
        "download_mitigations": "Download Mitigations",
        "dread_header": "DREAD Risk Assessment",
        "dread_code": "DREAD Assessment Code:",
        "download_dread": "Download DREAD Assessment",
        "test_cases_header": "Test Cases",
        "test_cases_code": "Test Cases Code:",
        "download_test_cases": "Download Test Cases",
        "improvement_suggestions": "Improvement Suggestions",
        "classification_top_secret": "Top Secret",
        "classification_secret": "Secret",
        "classification_confidential": "Confidential",
        "classification_restricted": "Restricted",
        "classification_unclassified": "Unclassified",

        # DREAD Risk Assessment Components
        "dread_damage_potential": "Damage Potential",
        "dread_reproducibility": "Reproducibility",
        "dread_exploitability": "Exploitability",
        "dread_affected_users": "Affected Users",
        "dread_discoverability": "Discoverability",

        # Error Messages
        "error_generating": "Error generating",
        "api_key_required": "Please enter your API key to continue.",

        # Language Switcher
        "language_label": "Language / 语言:",
        "language_option_en": "English",
        "language_option_zh": "中文",
        "language_default_index_en": 0,
        "language_default_index_zh": 1,

        # File Upload
        "file_upload_label": "Upload files (optional):",
        "file_upload_help": "Upload additional files such as code snippets, architecture diagrams, or documentation to help with the threat modeling.",

        # Prompts
        "threat_model_prompt_expert": "Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology",
        "attack_tree_prompt_expert": "Act as a cyber security expert with more than 20 years experience of creating attack trees",
        "mitigations_prompt_expert": "Act as a cyber security expert with more than 20 years experience of implementing security controls",
        "dread_prompt_expert": "Act as a cyber security expert with more than 20 years experience of using the DREAD risk assessment methodology",
        "test_cases_prompt_expert": "Act as a cyber security expert with more than 20 years experience of security testing applications",

        # Sidebar sections
        "about_header": "About",
        "about_welcome": "Welcome to STRIDE GPT, an AI-powered tool designed to help teams produce better threat models for their applications.",
        "about_description": "Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. STRIDE GPT aims to help teams produce more comprehensive threat models by leveraging the power of Large Language Models (LLMs) to generate a threat list, attack tree and/or mitigating controls for an application based on the details provided.",
        "about_created_by": "Created by [Matt Adams](https://www.linkedin.com/in/matthewrwadams/).",
        "example_app_header": "Example Application Description",
        "example_app_description": "Below is an example application description that you can use to test STRIDE GPT:",
        "faqs_header": "FAQs",
        "faqs_stride_question": "### **What is STRIDE?**",
        "faqs_stride_answer": "STRIDE is a threat modeling methodology that helps to identify and categorise potential security risks in software applications. It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.",
        "faqs_how_works_question": "### **How does STRIDE GPT work?**",
        "faqs_how_works_answer": "When you enter an application description and other relevant details, the tool will use a GPT model to generate a threat model for your application. The model uses the application description and details to generate a list of potential threats and then categorises each threat according to the STRIDE methodology.",
        "faqs_storage_question": "### **Do you store the application details provided?**",
        "faqs_storage_answer": "No, STRIDE GPT does not store your application description or other details. All entered data is deleted after you close the browser tab.",
        "faqs_slow_question": "### **Why does it take so long to generate a threat model?**",
        "faqs_slow_answer": "If you are using a free OpenAI API key, it will take a while to generate a threat model. This is because the free API key has strict rate limits. To speed up the process, you can use a paid API key.",
        "faqs_accuracy_question": "### **Are the threat models 100% accurate?**",
        "faqs_accuracy_answer": "No, the threat models are not 100% accurate. STRIDE GPT uses GPT Large Language Models (LLMs) to generate its output. The GPT models are powerful, but they sometimes makes mistakes and are prone to 'hallucinations' (generating irrelevant or inaccurate content). Please use the output only as a starting point for identifying and addressing potential security risks in your applications.",
        "faqs_improve_question": "### **How can I improve the accuracy of the threat models?**",
        "faqs_improve_answer": "You can improve the accuracy of the threat models by providing a detailed description of the application and selecting the correct application type, authentication methods, and other relevant details. The more information you provide, the more accurate the threat models will be.",

        # Model provider section
        "model_selection_label": "Select the model you would like to use:",
        "anthropic_api_key_label": "Enter your Anthropic API key:",
        "anthropic_api_key_help": "You can find your Anthropic API key on the [Anthropic console](https://console.anthropic.com/settings/keys).",
        "anthropic_model_help": "Claude 4 models are the latest generation with enhanced capabilities. Claude Sonnet 4 offers the best balance of performance and efficiency.",
        "azure_api_key_label": "Azure OpenAI API key:",
        "azure_api_key_help": "You can find your Azure OpenAI API key on the [Azure portal](https://portal.azure.com/).",
        "azure_endpoint_label": "Azure OpenAI endpoint:",
        "azure_endpoint_help": "You can find your Azure OpenAI endpoint on the [Azure portal](https://portal.azure.com/).",
        "azure_version_label": "Azure OpenAI API version:",
        "azure_version_help": "You can find your Azure OpenAI API version on the [Azure portal](https://portal.azure.com/).",
        "azure_deployment_label": "Azure OpenAI deployment name:",
        "azure_deployment_help": "You can find your Azure OpenAI deployment name on the [Azure portal](https://portal.azure.com/).",
        "google_api_key_label": "Enter your Google AI API key:",
        "google_api_key_help": "You can generate a Google AI API key in the [Google AI Studio](https://makersuite.google.com/app/apikey).",
        "google_model_help": "Gemini 2.5 Pro/Flash are Google's latest preview models with 1M token context and enhanced thinking capabilities that show model reasoning. Gemini 2.0 Flash is a capable model, while Gemini 2.0 Flash Lite is more cost-effective.",
        "mistral_api_key_label": "Enter your Mistral API key:",
        "mistral_api_key_help": "You can generate a Mistral API key in the [Mistral console](https://console.mistral.ai/api-keys/).",
        "mistral_model_help": "Mistral Large is the most powerful model with advanced reasoning capabilities. Mistral Small is more cost-effective for simpler tasks.",
        "ollama_endpoint_label": "Enter your Ollama endpoint:",
        "ollama_endpoint_help": "Enter the URL of your Ollama instance (e.g., http://localhost:11434).",
        "ollama_model_help": "Select the Ollama model you want to use. Make sure the model is available in your Ollama instance.",
        "lm_studio_endpoint_label": "Enter your LM Studio Server endpoint:",
        "lm_studio_endpoint_help": "Enter the URL of your LM Studio Server instance (e.g., http://localhost:1234).",
        "lm_studio_model_help": "Select the LM Studio model you want to use. Make sure the model is loaded in LM Studio.",
        "groq_api_key_label": "Enter your Groq API key:",
        "groq_api_key_help": "You can find your Groq API key on the [Groq console](https://console.groq.com/keys).",
        "groq_model_help": "Groq Llama 3.2 models offer excellent performance with fast inference times. Mixtral 8x22B is a powerful mixture-of-experts model.",
        "glm_api_key_label": "Enter your GLM API key:",
        "glm_api_key_help": "You can get your GLM API key from the [BigModel console](https://open.bigmodel.cn/).",
        "glm_model_help": "GLM-4-Plus is the latest flagship model with enhanced capabilities. GLM-4-Air offers a good balance of performance and cost-effectiveness.",

        # Error messages
        "lm_studio_connect_error": """Unable to connect to LM Studio Server. Please ensure:
1. LM Studio is running and the local server is started
2. The endpoint URL is correct (default: http://localhost:1234)
3. No firewall is blocking the connection""",
        "lm_studio_fetch_error": "Error fetching models from LM Studio Server: {}\n\nPlease check:\n1. LM Studio is properly configured and running\n2. The models are loaded in LM Studio",
        "ollama_no_models_error": """No models found in Ollama. Please ensure you have:
1. Pulled at least one model using 'ollama pull <model_name>'
2. The model download completed successfully""",
        "ollama_connect_error": """Unable to connect to Ollama. Please ensure:
1. Ollama is installed and running
2. The endpoint URL is correct (default: http://localhost:11434)
3. No firewall is blocking the connection""",
        "ollama_timeout_error": """Request to Ollama timed out. Please check:
1. Ollama is responding and not overloaded
2. Your network connection is stable
3. The endpoint URL is accessible""",
        "ollama_invalid_response_error": """Received invalid response from Ollama. Please verify:
1. You're running a compatible version of Ollama
2. The endpoint URL is pointing to Ollama and not another service""",
        "ollama_unexpected_error": """Unexpected error fetching Ollama models: {}

Please check:
1. Ollama is properly installed and running
2. You have pulled at least one model
3. You have sufficient system resources""",

        # Step-by-step instructions
        "step_enter_api_key": "1. Enter your {} API key and chosen model below 🔑",
        "step_enter_azure_details": "1. Enter your Azure OpenAI API key, endpoint and deployment name below 🔑",
        "step_enter_endpoint": "1. Enter your {} endpoint below 🔑",
        "step_provide_details": "2. Provide details of the application that you would like to threat model  📝",
        "step_generate_output": "3. Generate a threat list, attack tree and/or mitigating controls for your application 🚀",

        # Main app content
        "threat_model_description": "A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.",
        "attack_tree_description": "Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system vulnerabilities and prioritising mitigation efforts.",
        "mitigations_description": "Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance the security posture of the application and protect against potential attacks.",
        "dread_description": "DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.",
        "test_cases_description": "Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test scenarios.",

        # UI messages and labels
        "upload_architecture_diagram": "Upload architecture diagram",
        "please_enter_api_key": "Please enter your {} API key to analyse the image.",
        "failed_to_analyze": "Failed to analyze the image. Please check the API key and try again.",
        "error_analyzing_image": "An error occurred while analyzing the image: {}",
        "analysing_threats": "Analysing potential threats...",
        "generating_attack_tree": "Generating attack tree...",
        "suggesting_mitigations": "Suggesting mitigations...",
        "generating_dread": "Generating DREAD Risk Assessment...",
        "generating_test_cases": "Generating test cases...",
        "generate_attack_tree": "Generate Attack Tree",
        "suggest_mitigations": "Suggest Mitigations",
        "generate_dread": "Generate DREAD Risk Assessment",
        "generate_test_cases": "Generate Test Cases",
        "attack_tree_code": "Attack Tree Code:",
        "attack_tree_preview": "Attack Tree Diagram Preview:",
        "download_diagram_code": "Download Diagram Code",
        "dread_assessment_header": "DREAD Risk Assessment",
        "dread_description": "The table below shows the DREAD risk assessment for each identified threat. The Risk Score is calculated as the average of the five DREAD categories.",
        "please_enter_app_details": "Please enter your application details before submitting.",
        "generate_threat_model_first": "Please generate a threat model first before {}.",
        "view_thinking_process": "View {}'s thinking process",
        "github_api_key_label": "Enter your GitHub API key (optional):",
        "github_api_key_help": "You can find or create your GitHub API key in your GitHub account settings under Developer settings > Personal access tokens.",
        "mistral_small_warning": "⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.",
        "local_llm_warning": "⚠️ Users may encounter syntax errors when generating attack trees using local LLMs. Experiment with different local LLMs to assess their output quality, or consider using a hosted model provider to generate attack trees.",
        "azure_info": "Please note that you must use an 1106-preview model deployment.",
        "azure_version": "Azure API Version: {}",

        # UI Elements that need i18n
        "github_url_label": "Enter GitHub repository URL (optional)",
        "github_url_help": "Enter the URL of the GitHub repository you want to analyze.",
        "github_api_key_warning": "Please enter a GitHub API key to analyze the repository.",
        "analyzing_github_repo": "Analyzing GitHub repository...",
        "app_input_placeholder": "Enter your application details...",
        "advanced_settings": "Advanced Settings",
        "github_token_limit_label": "Maximum token limit for GitHub analysis:",
        "github_token_limit_help": "Set the maximum number of tokens to use for GitHub repository analysis. This helps prevent exceeding your model's context window.",

        # Gerrit Repository Analysis
        "gerrit_url_label": "Enter Gerrit repository URL (optional):",
        "gerrit_url_help": "Enter the URL of the Gerrit repository you want to analyze (e.g., https://gerrit.example.com/project/repo).",
        "gerrit_username_label": "Enter your Gerrit username (optional):",
        "gerrit_username_help": "Enter your Gerrit username for authentication.",
        "gerrit_password_label": "Enter your Gerrit password or HTTP password (optional):",
        "gerrit_password_help": "Enter your Gerrit password or HTTP password for authentication.",
        "gerrit_api_key_warning": "Please enter your Gerrit username and password to analyze the repository.",
        "analyzing_gerrit_repo": "Analyzing Gerrit repository...",
        "gerrit_token_limit_label": "Maximum token limit for Gerrit analysis:",
        "gerrit_token_limit_help": "Set the maximum number of tokens to use for Gerrit repository analysis. This helps prevent exceeding your model's context window.",
        "repo_type_github": "GitHub",
        "repo_type_gerrit": "Gerrit",

        # Application Types
        "app_type_web": "Web application",
        "app_type_mobile": "Mobile application",
        "app_type_desktop": "Desktop application",
        "app_type_cloud": "Cloud application",
        "app_type_iot": "IoT application",
        "app_type_other": "Other",

        # Authentication Options
        "auth_none": "None",
        "auth_yes": "Yes",
        "auth_no": "No",

        # Error Messages and Notifications
        "threat_model_generation_issue": "There was an issue generating the threat model. The model may have returned a response in an unexpected format. You can try:",
        "retry_generation": "Running the generation again",
        "check_logs": "Checking the application logs for more details",
        "use_different_model": "Using a different model if the issue persists",
        "error_generating_threat_model": "Error generating threat model after {} attempts: {}",
        "retrying_threat_model": "Error generating threat model. Retrying attempt {}/{}...",
        "error_generating_attack_tree": "Error generating attack tree: {}",
        "error_generating_mitigations": "Error suggesting mitigations after {} attempts: {}",
        "retrying_mitigations": "Error suggesting mitigations. Retrying attempt {}/{}...",
        "suggesting_mitigations": "suggesting mitigations",
        "error_generating_dread": "Error generating DREAD risk assessment after {} attempts: {}",
        "debug_no_threats": "Debug: No threats were found in the response. Please try generating the threat model again.",
        "retrying_dread": "Error generating DREAD risk assessment. Retrying attempt {}/{}...",
        "debug_empty_dread": "Debug: The DREAD assessment response is empty. Please ensure you have generated a threat model first.",
        "requesting_dread": "requesting a DREAD risk assessment",
        "error_generating_test_cases": "Error generating test cases after {} attempts: {}",
        "retrying_test_cases": "Error generating test cases. Retrying attempt {}/{}...",
        "requesting_test_cases": "requesting test cases",
    }

    ZH = {
        # Main UI
        "app_title": "STRIDE GPT",
        "sidebar_header": "如何使用 STRIDE GPT",
        "model_provider_label": "选择您偏好的模型提供商：",
        "model_provider_help": "选择您想要使用的模型提供商。这将决定可供选择的模型。",

        # OpenAI Section
        "openai_instructions": """
1. 在下方输入您的 [OpenAI API 密钥](https://platform.openai.com/account/api-keys) 和选择的模型 🔑
2. 提供您想要进行威胁建模的应用程序详情  📝
3. 为您的应用程序生成威胁列表、攻击树和/或缓解控制措施 🚀
""",
        "openai_api_key_label": "输入您的 OpenAI API 密钥：",
        "openai_api_key_help": "您可以在 [OpenAI 控制台](https://platform.openai.com/account/api-keys) 找到您的 API 密钥。",
        "openai_model_label": "选择您想要使用的模型：",
        "openai_model_help": "GPT-4.1 是 OpenAI 最先进的模型，具有 1M token 上下文。o1、o3、o3-mini 和 o4-mini 是推理模型，在响应前执行复杂推理。o3 和 o4-mini 是具有卓越推理能力和 200K token 上下文的更新模型。",

        # GLM Section
        "glm_instructions": """
1. 在下方输入您的 [GLM API 密钥](https://open.bigmodel.cn/) 和选择的模型 🔑
2. 提供您想要进行威胁建模的应用程序详情  📝
3. 为您的应用程序生成威胁列表、攻击树和/或缓解控制措施 🚀
""",
        "glm_api_key_label": "输入您的 GLM API 密钥：",
        "glm_api_key_help": "您可以在 [BigModel 控制台](https://open.bigmodel.cn/) 找到您的 API 密钥。",
        "glm_model_label": "选择您想要使用的 GLM 模型：",
        "glm_model_help": "GLM-4.5 是具有强大推理能力的最新模型。GLM-4.5-air 针对速度进行了优化。",

        # Anthropic Section
        "anthropic_instructions": """
1. 在下方输入您的 [Anthropic API 密钥](https://console.anthropic.com/settings/keys) 和选择的模型 🔑
2. 提供您想要进行威胁建模的应用程序详情  📝
3. 为您的应用程序生成威胁列表、攻击树和/或缓解控制措施 🚀
""",
        "anthropic_api_key_label": "输入您的 Anthropic API 密钥：",
        "anthropic_api_key_help": "您可以在 [Anthropic 控制台](https://console.anthropic.com/settings/keys) 找到您的 API 密钥。",
        "anthropic_model_label": "选择您想要使用的 Anthropic 模型：",

        # Main App Section
        "app_description_header": "应用程序描述",
        "app_description_help": "输入您想要进行威胁建模的应用程序详情。",
        "app_type_label": "您正在对什么类型的应用程序进行威胁建模？",
        "app_type_help": "选择您正在进行威胁建模的应用程序类型。",
        "auth_label": "应用程序是否具有身份验证？",
        "auth_help": "指示应用程序是否具有任何形式的身份验证。",
        "internet_facing_label": "应用程序是否面向互联网？",
        "internet_facing_help": "指示应用程序是否可以从互联网访问。",
        "sensitive_data_label": "应用程序是否处理敏感数据？",
        "sensitive_data_help": "指示应用程序是否处理敏感数据，如个人身份信息、财务信息或健康记录。",
        "app_input_label": "请提供应用程序的描述，包括其架构、使用的技术和主要功能：",
        "app_input_help": "尽可能详细地提供应用程序的信息，包括其架构、使用的技术和主要功能。您也可以包括代码片段或文档链接。",
        "analyze_button": "分析应用程序",

        # Threat Model Section
        "threat_model_header": "威胁模型",
        "threat_model_code": "威胁模型代码：",
        "download_threat_model": "下载威胁模型",
        "attack_tree_header": "攻击树",
        "attack_tree_code": "攻击树代码：",
        "download_attack_tree": "下载攻击树代码",
        "open_mermaid_live": "打开 Mermaid Live",
        "mitigations_header": "缓解措施",
        "mitigations_code": "缓解措施代码：",
        "download_mitigations": "下载缓解措施",
        "dread_header": "DREAD 风险评估",
        "dread_code": "DREAD 评估代码：",
        "download_dread": "下载 DREAD 评估",
        "test_cases_header": "测试用例",
        "test_cases_code": "测试用例代码：",
        "download_test_cases": "下载测试用例",
        "improvement_suggestions": "改进建议",
        "classification_top_secret": "绝密",
        "classification_secret": "机密",
        "classification_confidential": "秘密",
        "classification_restricted": "限制",
        "classification_unclassified": "公开",

        # DREAD 风险评估组件
        "dread_damage_potential": "损害潜力",
        "dread_reproducibility": "可重现性",
        "dread_exploitability": "可利用性",
        "dread_affected_users": "受影响用户",
        "dread_discoverability": "可发现性",

        # Error Messages
        "error_generating": "生成错误",
        "api_key_required": "请输入您的 API 密钥以继续。",

        # Language Switcher
        "language_label": "Language / 语言:",
        "language_option_en": "English",
        "language_option_zh": "中文",
        "language_default_index_en": 0,
        "language_default_index_zh": 1,

        # Model provider section
        "model_selection_label": "选择您要使用的模型：",
        "anthropic_api_key_label": "输入您的 Anthropic API 密钥：",
        "anthropic_api_key_help": "您可以在 [Anthropic 控制台](https://console.anthropic.com/settings/keys) 找到您的 API 密钥。",
        "anthropic_model_help": "Claude 4 模型是具有增强功能的最新一代模型。Claude Sonnet 4 在性能和效率之间提供了最佳平衡。",
        "azure_api_key_label": "Azure OpenAI API 密钥：",
        "azure_api_key_help": "您可以在 [Azure 门户](https://portal.azure.com/) 找到您的 Azure OpenAI API 密钥。",
        "azure_endpoint_label": "Azure OpenAI 端点：",
        "azure_endpoint_help": "您可以在 [Azure 门户](https://portal.azure.com/) 找到您的 Azure OpenAI 端点。",
        "azure_version_label": "Azure OpenAI API 版本：",
        "azure_version_help": "您可以在 [Azure 门户](https://portal.azure.com/) 找到您的 Azure OpenAI API 版本。",
        "azure_deployment_label": "Azure OpenAI 部署名称：",
        "azure_deployment_help": "您可以在 [Azure 门户](https://portal.azure.com/) 找到您的 Azure OpenAI 部署名称。",
        "google_api_key_label": "输入您的 Google AI API 密钥：",
        "google_api_key_help": "您可以在 [Google AI Studio](https://makersuite.google.com/app/apikey) 生成 Google AI API 密钥。",
        "google_model_help": "Gemini 2.5 Pro/Flash 是 Google 最新的预览模型，具有 1M token 上下文和增强的思考功能，可以显示模型推理过程。Gemini 2.0 Flash 是一个功能强大的模型，而 Gemini 2.0 Flash Lite 更具成本效益。",
        "mistral_api_key_label": "输入您的 Mistral API 密钥：",
        "mistral_api_key_help": "您可以在 [Mistral 控制台](https://console.mistral.ai/api-keys/) 生成 Mistral API 密钥。",
        "mistral_model_help": "Mistral Large 是最强大的模型，具有先进的推理能力。Mistral Small 对于简单任务更具成本效益。",
        "ollama_endpoint_label": "输入您的 Ollama 端点：",
        "ollama_endpoint_help": "输入您的 Ollama 实例的 URL（例如：http://localhost:11434）。",
        "ollama_model_help": "选择您要使用的 Ollama 模型。确保该模型在您的 Ollama 实例中可用。",
        "lm_studio_endpoint_label": "输入您的 LM Studio Server 端点：",
        "lm_studio_endpoint_help": "输入您的 LM Studio Server 实例的 URL（例如：http://localhost:1234）。",
        "lm_studio_model_help": "选择您要使用的 LM Studio 模型。确保该模型已在 LM Studio 中加载。",
        "groq_api_key_label": "输入您的 Groq API 密钥：",
        "groq_api_key_help": "您可以在 [Groq 控制台](https://console.groq.com/keys) 找到您的 Groq API 密钥。",
        "groq_model_help": "Groq Llama 3.2 模型提供卓越的性能和快速的推理时间。Mixtral 8x22B 是一个强大的专家混合模型。",
        "glm_api_key_label": "输入您的 GLM API 密钥：",
        "glm_api_key_help": "您可以从 [BigModel 控制台](https://open.bigmodel.cn/) 获取您的 GLM API 密钥。",
        "glm_model_help": "GLM-4-Plus 是具有增强功能的最新旗舰模型。GLM-4-Air 在性能和成本效益之间提供了良好的平衡。",

        # Error messages
        "lm_studio_connect_error": """无法连接到 LM Studio Server。请确保：
1. LM Studio 正在运行且本地服务器已启动
2. 端点 URL 正确（默认：http://localhost:1234）
3. 没有防火墙阻止连接""",
        "lm_studio_fetch_error": "从 LM Studio Server 获取模型时出错：{}\n\n请检查：\n1. LM Studio 已正确配置并运行\n2. 模型已在 LM Studio 中加载",
        "ollama_no_models_error": """在 Ollama 中未找到模型。请确保您已：
1. 使用 'ollama pull <model_name>' 拉取了至少一个模型
2. 模型下载已成功完成""",
        "ollama_connect_error": """无法连接到 Ollama。请确保：
1. Ollama 已安装并正在运行
2. 端点 URL 正确（默认：http://localhost:11434）
3. 没有防火墙阻止连接""",
        "ollama_timeout_error": """请求 Ollama 超时。请检查：
1. Ollama 正在响应且未过载
2. 您的网络连接稳定
3. 端点 URL 可访问""",
        "ollama_invalid_response_error": """从 Ollama 收到无效响应。请验证：
1. 您正在运行兼容版本的 Ollama
2. 端点 URL 指向 Ollama 而不是其他服务""",
        "ollama_unexpected_error": """获取 Ollama 模型时发生意外错误：{}

请检查：
1. Ollama 已正确安装并运行
2. 您已拉取至少一个模型
3. 您有足够的系统资源""",

        # Step-by-step instructions
        "step_enter_api_key": "1. 在下方输入您的 {} API 密钥并选择模型 🔑",
        "step_enter_azure_details": "1. 在下方输入您的 Azure OpenAI API 密钥、端点和部署名称 🔑",
        "step_enter_endpoint": "1. 在下方输入您的 {} 端点 🔑",
        "step_provide_details": "2. 提供您想要进行威胁建模的应用程序的详细信息 📝",
        "step_generate_output": "3. 为您的应用程序生成威胁列表、攻击树和/或缓解控制措施 🚀",

        # File Upload
        "file_upload_label": "上传文件（可选）：",
        "file_upload_help": "上传附加文件，如代码片段、架构图或文档，以帮助进行威胁建模。",

        # Prompts
        "threat_model_prompt_expert": "作为一名拥有超过20年STRIDE威胁建模方法经验的网络安全专家",
        "attack_tree_prompt_expert": "作为一名拥有超过20年创建攻击树经验的网络安全专家",
        "mitigations_prompt_expert": "作为一名拥有超过20年实施安全控制经验的网络安全专家",
        "dread_prompt_expert": "作为一名拥有超过20年DREAD风险评估方法经验的网络安全专家",
        "test_cases_prompt_expert": "作为一名拥有超过20年安全测试应用程序经验的网络安全专家",

        # Sidebar sections
        "about_header": "关于",
        "about_welcome": "欢迎使用STRIDE GPT，这是一个AI驱动的工具，旨在帮助团队为他们的应用程序生成更好的威胁模型。",
        "about_description": "威胁建模是软件开发生命周期中的关键活动，但经常被忽视或执行不当。STRIDE GPT旨在通过利用大型语言模型（LLM）的力量，根据提供的详细信息为应用程序生成威胁列表、攻击树和/或缓解控制措施，从而帮助团队生成更全面的威胁模型。",
        "about_created_by": "由[Matt Adams](https://www.linkedin.com/in/matthewrwadams/)创建。",
        "example_app_header": "示例应用程序描述",
        "example_app_description": "以下是一个示例应用程序描述，您可以用来测试STRIDE GPT：",
        "faqs_header": "常见问题",
        "faqs_stride_question": "### **什么是STRIDE？**",
        "faqs_stride_answer": "STRIDE是一种威胁建模方法，有助于识别和分类软件应用程序中潜在的安全风险。它代表**S**poofing（欺骗）、**T**ampering（篡改）、**R**epudiation（否认）、**I**nformation Disclosure（信息泄露）、**D**enial of Service（拒绝服务）和**E**levation of Privilege（权限提升）。",
        "faqs_how_works_question": "### **STRIDE GPT如何工作？**",
        "faqs_how_works_answer": "当您输入应用程序描述和其他相关详细信息时，该工具将使用GPT模型为您的应用程序生成威胁模型。该模型使用应用程序描述和详细信息来生成潜在威胁列表，然后根据STRIDE方法对每个威胁进行分类。",
        "faqs_storage_question": "### **您会存储提供的应用程序详细信息吗？**",
        "faqs_storage_answer": "不，STRIDE GPT不会存储您的应用程序描述或其他详细信息。所有输入的数据在关闭浏览器标签页后都会被删除。",
        "faqs_slow_question": "### **为什么生成威胁模型需要这么长时间？**",
        "faqs_slow_answer": "如果您使用免费的OpenAI API密钥，生成威胁模型需要一些时间。这是因为免费API密钥有严格的速率限制。为了加快进程，您可以使用付费API密钥。",
        "faqs_accuracy_question": "### **威胁模型100%准确吗？**",
        "faqs_accuracy_answer": "不，威胁模型并非100%准确。STRIDE GPT使用GPT大型语言模型（LLM）生成其输出。GPT模型很强大，但有时会犯错误，并且容易出现'幻觉'（生成不相关或不准确的内容）。请仅将输出作为识别和解决应用程序中潜在安全风险的起点。",
        "faqs_improve_question": "### **如何提高威胁模型的准确性？**",
        "faqs_improve_answer": "您可以通过提供应用程序的详细描述并选择正确的应用程序类型、身份验证方法和其他相关详细信息来提高威胁模型的准确性。您提供的信息越多，威胁模型就越准确。",

        # Main app content
        "threat_model_description": "威胁模型有助于识别和评估对应用程序/系统的潜在安全威胁。它提供了一种系统化的方法来理解可能的漏洞和攻击向量。使用此选项卡使用STRIDE方法生成威胁模型。",
        "attack_tree_description": "攻击树是分析系统安全性的结构化方法。它们以分层格式表示潜在的攻击场景，攻击者的最终目标在根部，实现该目标的各种路径作为分支。这有助于理解系统漏洞并优先考虑缓解工作。",
        "mitigations_description": "使用此选项卡为威胁模型中识别的威胁生成潜在的缓解措施。缓解措施是安全控制或对策，可以帮助减少安全威胁的可能性或影响。生成的缓解措施可用于增强应用程序的安全态势并防止潜在攻击。",
        "dread_description": "DREAD是一种用于评估和优先处理与安全威胁相关的风险的方法。它根据**D**amage（损害潜力）、**R**eproducibility（可复制性）、**E**xploitability（可利用性）、**A**ffected users（受影响用户）和**D**iscoverability（可发现性）来评估威胁。这有助于确定总体风险级别并首先关注最关键的威胁。使用此选项卡为您的应用程序/系统执行DREAD风险评估。",
        "test_cases_description": "测试用例用于验证应用程序的安全性，并确保识别和解决潜在的漏洞。此选项卡允许您使用Gherkin语法生成测试用例。Gherkin提供了一种结构化的方式来描述应用程序行为，使用简单的Given-When-Then语句语法。这有助于创建清晰且可执行的测试场景。",

        # UI messages and labels
        "upload_architecture_diagram": "上传架构图",
        "please_enter_api_key": "请输入您的{} API密钥以分析图像。",
        "failed_to_analyze": "无法分析图像。请检查API密钥并重试。",
        "error_analyzing_image": "分析图像时发生错误：{}",
        "analysing_threats": "正在分析潜在威胁...",
        "generating_attack_tree": "正在生成攻击树...",
        "suggesting_mitigations": "正在建议缓解措施...",
        "generating_dread": "正在生成DREAD风险评估...",
        "generating_test_cases": "正在生成测试用例...",
        "generate_attack_tree": "生成攻击树",
        "suggest_mitigations": "建议缓解措施",
        "generate_dread": "生成DREAD风险评估",
        "generate_test_cases": "生成测试用例",
        "attack_tree_code": "攻击树代码：",
        "attack_tree_preview": "攻击树图预览：",
        "download_diagram_code": "下载图表代码",
        "dread_assessment_header": "DREAD风险评估",
        "dread_description": "下表显示了每个已识别威胁的DREAD风险评估。风险分数计算为五个DREAD类别的平均值。",
        "please_enter_app_details": "请在提交前输入您的应用程序详细信息。",
        "generate_threat_model_first": "请先生成威胁模型，然后再{}。",
        "view_thinking_process": "查看{}的思考过程",
        "github_api_key_label": "输入您的GitHub API密钥（可选）：",
        "github_api_key_help": "您可以在GitHub账户设置的Developer settings > Personal access tokens下找到或创建您的GitHub API密钥。",
        "mistral_small_warning": "⚠️ Mistral Small无法可靠地生成语法正确的Mermaid代码。请使用Mistral Large模型生成攻击树，或选择其他模型提供商。",
        "local_llm_warning": "⚠️ 使用本地LLM生成攻击树时可能会遇到语法错误。尝试使用不同的本地LLM来评估其输出质量，或考虑使用托管模型提供商生成攻击树。",
        "azure_info": "请注意，您必须使用1106-preview模型部署。",
        "azure_version": "Azure API版本：{}",

        # UI Elements that need i18n
        "github_url_label": "输入GitHub仓库URL（可选）",
        "github_url_help": "输入您想要分析的GitHub仓库URL。",
        "github_api_key_warning": "请输入GitHub API密钥以分析仓库。",
        "analyzing_github_repo": "正在分析GitHub仓库...",
        "app_input_placeholder": "输入您的应用程序详细信息...",
        "advanced_settings": "高级设置",
        "github_token_limit_label": "GitHub分析的最大令牌限制：",
        "github_token_limit_help": "设置用于GitHub仓库分析的最大令牌数。这有助于防止超出模型的上下文窗口。",

        # Gerrit 仓库分析
        "gerrit_url_label": "输入Gerrit仓库URL（可选）：",
        "gerrit_url_help": "输入您想要分析的Gerrit仓库URL（例如：https://gerrit.example.com/project/repo）。",
        "gerrit_username_label": "输入您的Gerrit用户名（可选）：",
        "gerrit_username_help": "输入您的Gerrit用户名进行身份验证。",
        "gerrit_password_label": "输入您的Gerrit密码或HTTP密码（可选）：",
        "gerrit_password_help": "输入您的Gerrit密码或HTTP密码进行身份验证。",
        "gerrit_api_key_warning": "请输入您的Gerrit用户名和密码以分析仓库。",
        "analyzing_gerrit_repo": "正在分析Gerrit仓库...",
        "gerrit_token_limit_label": "Gerrit分析的最大令牌限制：",
        "gerrit_token_limit_help": "设置用于Gerrit仓库分析的最大令牌数。这有助于防止超出模型的上下文窗口。",
        "repo_type_github": "GitHub",
        "repo_type_gerrit": "Gerrit",

        # Application Types
        "app_type_web": "Web应用程序",
        "app_type_mobile": "移动应用程序",
        "app_type_desktop": "桌面应用程序",
        "app_type_cloud": "云应用程序",
        "app_type_iot": "物联网应用程序",
        "app_type_other": "其他",

        # Authentication Options
        "auth_none": "无",
        "auth_yes": "是",
        "auth_no": "否",

        # Error Messages and Notifications
        "threat_model_generation_issue": "生成威胁模型时出现问题。模型可能返回了意外格式的响应。您可以尝试：",
        "retry_generation": "再次运行生成",
        "check_logs": "检查应用程序日志以获取更多详细信息",
        "use_different_model": "如果问题持续存在，请使用不同的模型",
        "error_generating_threat_model": "在{}次尝试后生成威胁模型时出错：{}",
        "retrying_threat_model": "生成威胁模型时出错。重试尝试 {}/{}...",
        "error_generating_attack_tree": "生成攻击树时出错：{}",
        "error_generating_mitigations": "在{}次尝试后建议缓解措施时出错：{}",
        "retrying_mitigations": "建议缓解措施时出错。重试尝试 {}/{}...",
        "suggesting_mitigations": "建议缓解措施",
        "error_generating_dread": "在{}次尝试后生成DREAD风险评估时出错：{}",
        "debug_no_threats": "调试：响应中未找到威胁。请尝试再次生成威胁模型。",
        "retrying_dread": "生成DREAD风险评估时出错。重试尝试 {}/{}...",
        "debug_empty_dread": "调试：DREAD评估响应为空。请确保您已先生成威胁模型。",
        "requesting_dread": "请求DREAD风险评估",
        "error_generating_test_cases": "在{}次尝试后生成测试用例时出错：{}",
        "retrying_test_cases": "生成测试用例时出错。重试尝试 {}/{}...",
        "requesting_test_cases": "请求测试用例",
    }

def get_text(key, language="en"):
    """Get translated text for a given key and language"""
    if language == "zh":
        return translations.ZH.get(key, translations.EN.get(key, key))
    return translations.EN.get(key, key)

def get_prompt_language_suffix(language):
    """Get language suffix for prompts"""
    if language == "zh":
        return "请用中文回答。"
    return ""