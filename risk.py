import streamlit as st
import json
import pandas as pd
import os
# ##---------Config--------------------------
st.set_page_config(page_title="DIWAR", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
    <style>
        .reportview-container {
            margin-top: -2em;
        }
        #MainMenu {visibility: hidden;}
        .stDeployButton {display:none;}
        footer {visibility: hidden;}
        #stDecoration {display:none;}
    </style>
""", unsafe_allow_html=True)
#-------------------------------------------
def configure_sidebar(headers):
    # Generate CSS for each header
    css = "<style>"
    for idx, (header_text, header_color) in enumerate(headers):
        css += f"""
        .header-{idx} {{
            color: {header_color};
        }}
        """
    css += "</style>"
    st.sidebar.markdown(css, unsafe_allow_html=True)

    # Store headers for later use
    st.session_state['headers'] = headers
def render_header(header_index):
    headers = st.session_state.get('headers', [])
    if header_index < len(headers):
        header_text, _ = headers[header_index]
        st.sidebar.markdown(f'<h2 class="header-{header_index}">{header_text}</h2>', unsafe_allow_html=True)
# ##-----Sidebar----------------------------
# st.sidebar.title("Digital Identity Wallet Analysis and Risk assessment")
base_path = os.getcwd()
logo_path = os.path.join(base_path, "d.png")
headers = [
    ("About", "#f3b61f"),
    ("How It Works", "#f3b61f")
]
configure_sidebar(headers)
# st.sidebar.image(logo_path, width=200)
# logo_path = "path_to_your_logo.png"  # Replace with the path to your logo image file

st.sidebar.image(logo_path, use_column_width=True)
render_header(0)
# st.sidebar.header("About")
st.sidebar.write("""
Welcome to D.I.W.A.R., a risk assessment tool. It helps evaluate and calculate risks associated with different entities in the context of a "Digital Identity Wallet" ecosystem. It assesses the relevant threats for each entity and suggests mitigation controls based on the selected entity's responsibilities.
""")
st.sidebar.write("""**D.I.W.A.R.** is an acronym for: **D**igital **I**dentity **W**allet **A**nalysis and **R**isk assessment.
""")
st.sidebar.write("""**Methodology:** DIWAR is a Control-based Risk Assessment tool designed to evaluate risks associated with various security threats by assessing the effectiveness of implemented controls. Central to this assessment is the **[DREAD model](https://en.wikipedia.org/wiki/DREAD_(risk_assessment_model))**, a framework used to quantify, evaluate, and prioritize threats based on DREAD factors.
                 
                 """)
# st.sidebar.markdown("""
# **Overview:**
# DIWAR is a Control-based Risk Assessment tool designed to evaluate risks associated with various security threats by assessing the effectiveness of implemented controls. Central to this assessment is the **DREAD model**, a framework used to quantify, evaluate, and prioritize threats based on five key factors:

# - **Damage Potential (D):** Refers to the potential impact that a vulnerability could have on the target. The target can be the organization, the system in question, or other users in general. It considers how much damage an exploit can cause if it is successfully executed.

# - **Reproducibility (R):** Refers to how easily an attacker can reproduce the vulnerability. This factor assesses the likelihood that an attacker can consistently exploit the vulnerability.

# - **Exploitability (E):** Refers to how easy or difficult it is to exploit the vulnerability. This factor considers the skill level required and the tools or resources needed to exploit the vulnerability.

# - **Affected Users (A):** Refers to the number of users who could be affected by the vulnerability. It evaluates the scope and scale of the potential impact on users if the vulnerability is exploited.

# - **Discoverability (D):** Refers to how easy or difficult it is to discover the vulnerability. This factor assesses the likelihood that the vulnerability will be found by attackers, considering the visibility and accessibility of the vulnerability.
# """)
render_header(1)
# st.sidebar.header("How It Works")
st.sidebar.write("""
1. **Select an Entity**: Choose an entity from the dropdown to view relevant threats and controls.
2. **Threat Assessment**: The tool lists all threats and controls that affect the selected entity.
3. **Control Selection**: Choose the level of implementation for each control and view the overall risk for the entity.
4. **View Risks**: The tool calculates and displays qualitative risks based on control implementation and threat data.
""")
st.sidebar.write("---")
st.sidebar.write("For more information or feedback, contact us at: st-diwar@fbk.eu")
# with st.sidebar:
#     _, center, _ = st.columns([0.2, 1, 0.2]) # Columns to center the image
#     with center:
#         st.image(logo_path, width=200)
#         # logo_path = "path_to_your_logo.png"  # Replace with the path to your logo image file
#         # st.sidebar.image(logo_path, use_column_width=True)
#         st.sidebar.header("About the D.I.W.A.R")
#         st.sidebar.write("""
#         The **Threat Risk Assessment Tool** helps evaluate and calculate risks associated with different roles in the context of a "Digital Identity Wallet" ecosystem. It assesses the relevant threats for each role and suggests mitigation controls based on the selected role's responsibilities.
#         """)
#         st.sidebar.header("How It Works")
#         st.sidebar.write("""
#         1. **Select a Role**: Choose a role from the dropdown to view relevant threats and controls.
#         2. **Threat Assessment**: The tool lists all threats and controls that affect the selected role.
#         3. **Control Selection**: Choose the level of implementation for each control and view the overall risk for the role.
#         4. **View Risks**: The tool calculates and displays qualitative risks based on control implementation and threat data.
#         """)
#         st.sidebar.write("---")
#         st.sidebar.write("For more information or feedback, contact us at: mmollaeefar@fbk.eu")

# ##-----------------------------------------


# Load the JSON files
file_path1 = "C:\\Users\\mmoll\\Desktop\\Py\\Threat-Model\\random-coding\\dread\\threats_controls.json"
with open(file_path1, 'r') as file:
    threats_data = json.load(file)

file_path2 = "C:\\Users\\mmoll\\Desktop\\Py\\Threat-Model\\random-coding\\dread\\controls_mitigations.json"
with open(file_path2, 'r') as file:
    controls_data = json.load(file)

file_path3 = "C:\\Users\\mmoll\\Desktop\\Py\\Threat-Model\\random-coding\\dread\\controls_dread.json"
with open(file_path3, 'r') as file:
    controls_dread = json.load(file)

file_path4 = "C:\\Users\\mmoll\\Desktop\\Py\\Threat-Model\\random-coding\\dread\\role_threats.json"
with open(file_path4, 'r') as file:
    role_threats_data = json.load(file)

# Constants
MAX_MITIGATION = 5
MITIGATION_LEVELS_MAPPING = {
    "N/A": 0,
    "Basic": 1,
    "Intermediate": 3,
    "Advanced": 5,
    "Yes": 5
}

# Qualitative risk matrix
qualitative_risk_matrix = {
    ("Low", "Low"): "Very Low",
    ("High", "High"): "Critical",
    ("Low", "Medium"): "Low",
    ("Low", "High"): "Medium",
    ("Medium", "Low"): "Low",
    ("Medium", "Medium"): "Medium",
    ("Medium", "High"): "High",
    ("High", "Low"): "Medium",
    ("High", "Medium"): "High"
}

# Function to map value to qualitative levels
def map_to_qualitative(value):
    if value == 0:
        return "No Risk"
    elif value <= 0.33:
        return "Low"
    elif value <= 0.67:
        return "Medium"
    else:
        return "High"

# Function to calculate maximum mitigation values for each factor
def calculate_max_sums(group, factors):
    max_sums = {factor: 0 for factor in factors}
    for row in group:
        weight = row['Weight']
        for factor in factors:
            if row[factor] == 'Yes':
                max_sums[factor] += weight * MAX_MITIGATION
    return max_sums

# Function to calculate mitigation values based on user inputs
def calculate_mitigation_sums(group, factors):
    mitigation_sums = {factor: 0 for factor in factors}
    for row in group:
        weight = row['Weight']
        mitigation_level = row['Mitigation Level']
        for factor in factors:
            if row[factor] == 'Yes':
                mitigation_sums[factor] += weight * mitigation_level
    return mitigation_sums

# Function to display control mitigation level selection
def display_control_mitigation_selection(threat_code, threats_data, selected_roles, controls_data):
    threat_controls = next((ctrl for ctrl in threats_data['Threats'] if ctrl['Code'] == threat_code), None)

    if threat_controls:
        filtered_controls = [
            control for control in threat_controls['Controls']
            if any(role in control['Role_Responsible'] for role in selected_roles)
        ]

        if not filtered_controls:
            st.warning(f"No controls found for the selected roles {selected_roles} and threat {threat_code}.")
            return {}

        user_responses = {}
        for control in filtered_controls:
            control_code = control['Code']
            control_name = controls_data['Controls'].get(control_code, {}).get('Mitigation Level', {})

            # Check if the control has special mitigation levels
            special_controls = ["C7", "C9", "C13", "C15", "C23", "C30", "C33", "C35"]
            if control_code in special_controls:
                mitigation_levels = ["N/A", "Yes"]
            else:
                mitigation_levels = ["N/A", "Basic", "Intermediate", "Advanced"]

            with st.expander(f"{control_code}) {control_name.get('Basic', 'Unknown Control')}"):
                if selected_role == "Holder":
                    # Display responsible roles for the control
                    responsible_roles = handle_special_control(control_code, threats_data)
                    st.markdown(
                        f"**Responsible role(s):** <span style='color:#f58f2f'> {', '.join(responsible_roles)}</span>",
                        unsafe_allow_html=True,
                    )

                selected_level = st.radio(
                    f"What is the level of implementation of the control {control_code}?",
                    mitigation_levels,
                    key=f"{threat_code}_{control_code}"
                )

                if selected_level != "N/A":
                    level_description = control_name.get(selected_level, "Description not available.")
                    st.write(f"**Selected mitigation level:** {level_description}")

                user_responses[control_code] = MITIGATION_LEVELS_MAPPING[selected_level]

        return user_responses
    else:
        st.warning(f"Threat code {threat_code} not found in the threats data.")
        return {}

# Function to perform risk assessment
def perform_risk_assessment(selected_threats, user_responses, threats_data, controls_dread, role_threats_data, selected_roles):
    results = {
        'Threat': [],
        'Impact Residue': [],
        'Likelihood Residue': [],
        'Qualitative Risk': [],
        'Controls': [] 
    }

    for threat_code, threat_name in selected_threats:
        threat_controls = next((ctrl for ctrl in threats_data['Threats'] if ctrl['Code'] == threat_code), None)

        if threat_controls:
            filtered_controls = [
                control for control in threat_controls['Controls']
                if any(role in control['Role_Responsible'] for role in selected_roles)
            ]

            group_data = []
            control_codes = []  # To store control codes for the Controls column

            for control in filtered_controls:
                control_code = control['Code']
                weight = control['Normalized Weights']
                mitigation_level = user_responses.get(control_code, 0)  # Default to 0 if no response

                control_details = next((ctrl for ctrl in controls_dread['Controls'] if ctrl['Code'] == control_code), None)
                if control_details:
                    group_data.append({
                        'Weight': weight,
                        'Mitigation Level': mitigation_level,
                        'D': control_details['D'],
                        'R': control_details['R'],
                        'E': control_details['E'],
                        'A': control_details['A'],
                        'D1': control_details['D1']
                    })

                control_codes.append(control_code)  # Collect control codes

            max_sums = calculate_max_sums(group_data, ['D', 'R', 'E', 'A', 'D1'])
            max_sum_impact_mitigation = max_sums['D'] + max_sums['A']
            max_sum_likelihood_mitigation = max_sums['R'] + max_sums['E'] + max_sums['D1']

            mitigation_sums = calculate_mitigation_sums(group_data, ['D', 'R', 'E', 'A', 'D1'])
            obtained_sum_impact = mitigation_sums['D'] + mitigation_sums['A']
            obtained_sum_likelihood = mitigation_sums['R'] + mitigation_sums['E'] + mitigation_sums['D1']
            # Compute the percentage of reduction of the control implementation
            # then the obtained value will be multiply by the Overall impact and likelihood which result having the impact and likhood risk
            # in this way, in case of not implementing any control we can have an idea (a prioritization of the risk of each threat) of the risk level at the beginning.
            impact_residue = round((max_sum_impact_mitigation - obtained_sum_impact) / max_sum_impact_mitigation, 2) if max_sum_impact_mitigation != 0 else 0
            likelihood_residue = round((max_sum_likelihood_mitigation - obtained_sum_likelihood) / max_sum_likelihood_mitigation, 2) if max_sum_likelihood_mitigation != 0 else 0

            threat_data = next(threat for role in selected_roles for threat in role_threats_data["Roles"][role]["threats"] if threat["Code"] == threat_code)

            impact_risk = (threat_data['Overall-Impact'] * impact_residue) / 5
            likelihood_risk = (threat_data['Overall-Likelihood'] * likelihood_residue) / 5
            impact_level = map_to_qualitative(impact_risk)
            likelihood_level = map_to_qualitative(likelihood_risk)

            qualitative_risk = "No Risk" if impact_residue == 0 or likelihood_residue == 0 else qualitative_risk_matrix.get((impact_level, likelihood_level))

            results['Threat'].append(threat_name)
            results['Impact Residue'].append(impact_risk)
            results['Likelihood Residue'].append(likelihood_risk)
            results['Qualitative Risk'].append(qualitative_risk)
            results['Controls'].append(", ".join(control_codes))  


    results_df = pd.DataFrame(results)

    def color_code_risk(val):
        color_map = {
            "Very Low": "background-color: #008000; color: #FFFFFF;",  # Green background, White text
            "Low": "background-color: #FFFF00; color: #000000;",       # Yellow background, Black text
            "Medium": "background-color: #A5762A; color: #FFFFFF;",    # Brown background, White text
            "High": "background-color: #ED7777; color: #FFFFFF;",      # Light Coral background, White text
            "Critical": "background-color: #ED0E0E; color: #FFFFFF;"   # Red background, White text
        }
        return color_map.get(val, "")

    styled_df = results_df.style.map(color_code_risk, subset=["Qualitative Risk"])

    return styled_df, results

# Function to handle the special feature for each control
def handle_special_control(control_code, threats_data):
    temp_list = []
    for threat in threats_data['Threats']:
        for control in threat['Controls']:
            if control['Code'] == control_code:
                for role in control['Role_Responsible']:
                    if role not in temp_list:
                        temp_list.append(role)

    if "Holder" in temp_list:
        temp_list.remove("Holder")

    return temp_list



# Define tabs
tab1, tab2 = st.tabs(["Risk Assessment", "Security Control View"])

# Add Role-Based Assessment tab
with tab1:
    st.write("This tool evaluates and calculates the risk associated with different entities in the context of \"Digital Identity Wallet\" by assessing threats and the mitigation controls implemented for each threat.")
    # Step 1: Select Roles (with placeholder option)

    st.markdown("""----""")
    st.subheader("Step 1: Select Affected Entity")
    roles_options = ["None"] + list(role_threats_data["Roles"].keys())

    selected_role = st.selectbox(
        "Select the entity that you want perform a risk assessment:",
        roles_options
    )

    if selected_role != "None":
        # Aggregate associated threats for selected role
        selected_threats = set()
        if selected_role == "Holder":
            for role in role_threats_data["Roles"].keys():
                associated_threats = role_threats_data["Roles"][role]['threats']
                for threat in associated_threats:
                    selected_threats.add((threat['Code'], threat['Name']))
        else:
            associated_threats = role_threats_data["Roles"][selected_role]['threats']
            for threat in associated_threats:
                selected_threats.add((threat['Code'], threat['Name']))

        # Display the associated threats below the dropdown
        st.write(f"#### Threats Associated with the {selected_role}:")
        for threat_code, threat_name in sorted(selected_threats):
            st.info(f"**{threat_code}**: {threat_name}")
        if selected_threats:
            # Step 2: Generate form for selected controls
            st.subheader("Step 2: Control Mitigation Level Selection")

            # Aggregate shared controls
            shared_controls = set()
            for threat_code, threat_name in selected_threats:
                threat_controls = next((ctrl for ctrl in threats_data['Threats'] if ctrl['Code'] == threat_code), None)
                if threat_controls:
                    for control in threat_controls['Controls']:
                        if selected_role == "Holder" or selected_role in control['Role_Responsible']:
                            shared_controls.add(control['Code'])

            user_responses = {}

            for control_code in shared_controls:
                control_name = next((ctrl['Name'] for ctrl in controls_dread['Controls'] if ctrl['Code'] == control_code), "Unknown Control")
                # Check if the control has special mitigation levels
                special_controls = ["C7", "C9", "C13", "C15", "C23", "C30", "C33", "C35"]
                if control_code in special_controls:
                    mitigation_levels = ["N/A", "Yes"]
                else:
                    mitigation_levels = ["N/A", "Basic", "Intermediate", "Advanced"]

                with st.expander(f"{control_code}) {control_name}"):
                    if selected_role == "Holder":
                        # Display responsible roles for the control
                        responsible_roles = handle_special_control(control_code, threats_data)
                        st.markdown(
                            f"**Responsible entity(s):** <span style='color:#f58f2f'> {', '.join(responsible_roles)}</span>",
                            unsafe_allow_html=True,
                        )

                    selected_level = st.radio(
                        f"What is the level of implementation of the control {control_code}?",
                        mitigation_levels,
                        key=f"shared_{control_code}"
                    )

                    if selected_level != "N/A":
                        level_description = controls_data['Controls'].get(control_code, {}).get('Mitigation Level', {}).get(selected_level, "Description not available.")
                        st.markdown(
                            f"**Selected mitigation level:** <span style='color:#f58f2f'> {level_description}</span>",
                            unsafe_allow_html=True,
                        )

                    user_responses[control_code] = MITIGATION_LEVELS_MAPPING[selected_level]

            # Step 3: Perform Risk Assessment
            if st.button("Risk Assessment"):
                styled_df, _ = perform_risk_assessment(list(selected_threats), user_responses, threats_data, controls_dread, role_threats_data, [selected_role])
                st.write("Risk Assessment Results")
                st.dataframe(styled_df)
        else:
            st.warning("No threats found for the selected entity.")
    else:
        st.warning("Please select an entity to proceed.")

### Tab 2: Security Control View - Display Controls Based on Selected Role
with tab2:
    st.write("This section allows you to view the controls associated with a specific entity and their implementation suggestions based on the entity's responsibilities.")
    st.markdown("""----""")
    # Step 1: Select Roles for the Role View
    roles_view_options = ["None"] + ["Issuer", "Verifier", "Wallet Provider"]

    selected_view_role = st.selectbox(
        "Select the entity to view related controls and threats:",
        roles_view_options
    )

    if selected_view_role:
        # Prepare to collect relevant controls and threats based on the selected role
        controls_dict = {}

        # Loop through threats and controls to filter by role responsibility
        for threat in threats_data['Threats']:
            threat_code = threat['Code']
            for control in threat['Controls']:
                if selected_view_role in control['Role_Responsible']:
                    control_code = control['Code']
                    control_name = next((ctrl['Name'] for ctrl in controls_dread['Controls'] if ctrl['Code'] == control_code), "Unknown Control")
                    implementation_choice = control.get('Implementation Choice', 'Unknown')

                    # Handle the special case where "Implementation Choice" is "Temp"
                    if implementation_choice == "Temp":
                        if selected_view_role == "Issuer" or selected_view_role == "Verifier":
                            implementation_choice = "Mandatory"
                        else:
                            implementation_choice = "Recommended"

                    # Add control and threat info to the dictionary
                    if control_code not in controls_dict:
                        controls_dict[control_code] = {
                            'Control Name': control_name,
                            'Implemented Indication': implementation_choice,
                            'Threats': set()
                        }
                    controls_dict[control_code]['Threats'].add(threat_code)

        # Prepare the data for display
        related_controls = []
        implemented_indication = []
        related_threats = []

        for control_code, control_data in controls_dict.items():
            related_controls.append(f"{control_code}) {control_data['Control Name']}")
            implemented_indication.append(control_data['Implemented Indication'])
            related_threats.append(", ".join(control_data['Threats']))  # Combine threats into a single string

        # Display results in a DataFrame
        if related_controls:
            data = {
                "Related Controls": related_controls,
                "Implemented Indication": implemented_indication,
                "Threats": related_threats
            }
            # Display the list of threats associated with the controls
            st.write(f"#### Threats Associated with the {selected_view_role}:")
            unique_threats = set()
            for control_data in controls_dict.values():
                unique_threats.update(control_data['Threats'])

            for threat_code in sorted(unique_threats):
                threat_name = next((threat['Name'] for threat in threats_data['Threats'] if threat['Code'] == threat_code), "Unknown Threat")
                st.info(f"**{threat_code}**: {threat_name}")

            df = pd.DataFrame(data)
            st.write("")
            st.write("")
            st.write(f"##### Controls, Implementation Indication, and Threats for: {selected_view_role}")
            st.dataframe(df)

            
        else:
            st.warning("Please select an entity to proceed.")