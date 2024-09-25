import streamlit as st
import json
import pandas as pd

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
    "Advanced": 5
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
            mitigation_levels = ["N/A", "Basic", "Intermediate", "Advanced"]

            with st.expander(f"{control_code}) {control_name.get('Basic', 'Unknown Control')}"):
                if selected_role == "All":
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
        'Qualitative Risk': []
    }

    for threat_code, threat_name in selected_threats:
        threat_controls = next((ctrl for ctrl in threats_data['Threats'] if ctrl['Code'] == threat_code), None)

        if threat_controls:
            filtered_controls = [
                control for control in threat_controls['Controls']
                if any(role in control['Role_Responsible'] for role in selected_roles)
            ]

            group_data = []
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

            max_sums = calculate_max_sums(group_data, ['D', 'R', 'E', 'A', 'D1'])
            max_sum_impact_mitigation = max_sums['D'] + max_sums['A']
            max_sum_likelihood_mitigation = max_sums['R'] + max_sums['E'] + max_sums['D1']

            mitigation_sums = calculate_mitigation_sums(group_data, ['D', 'R', 'E', 'A', 'D1'])
            obtained_sum_impact = mitigation_sums['D'] + mitigation_sums['A']
            obtained_sum_likelihood = mitigation_sums['R'] + mitigation_sums['E'] + mitigation_sums['D1']
            # Compute the percentage of reduction of the control implementation
            # then the obtain value will be multiply by the Overall impact and likelihood which result having the impact and likhood risk
            # in this way, in case of not implementing any control we can have an idea (a prioritization of the risk of each threat).
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

    if "All" in temp_list:
        temp_list.remove("All")

    return temp_list

# Streamlit application layout with tabs
st.title("Threat Risk Assessment Tool")

# Define tabs
tab1, tab2 = st.tabs(["Role Based", "Risk"])

# Add Role-Based Assessment tab
with tab1:
    st.write("This tool evaluates and calculates the risk associated with different roles in the context of \"Digital Identity Wallet\" by assessing threats and the mitigation controls implemented for each threat.")
    # Step 1: Select Roles (with placeholder option)
    st.subheader("Step 1: Select Role")
    roles_options = ["None"] + list(role_threats_data["Roles"].keys())

    selected_role = st.selectbox(
        "Select the role that is applicable in your scenario:",
        roles_options
    )

    if selected_role != "None":
        # Aggregate associated threats for selected role
        selected_threats = set()
        if selected_role == "All":
            for role in role_threats_data["Roles"].keys():
                associated_threats = role_threats_data["Roles"][role]['threats']
                for threat in associated_threats:
                    selected_threats.add((threat['Code'], threat['Name']))
        else:
            associated_threats = role_threats_data["Roles"][selected_role]['threats']
            for threat in associated_threats:
                selected_threats.add((threat['Code'], threat['Name']))

        # Display the associated threats below the dropdown
        st.write(f"#### Threats associated with the {selected_role} role:")
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
                        if selected_role == "All" or selected_role in control['Role_Responsible']:
                            shared_controls.add(control['Code'])

            user_responses = {}

            for control_code in shared_controls:
                control_name = next((ctrl['Name'] for ctrl in controls_dread['Controls'] if ctrl['Code'] == control_code), "Unknown Control")
                mitigation_levels = ["N/A", "Basic", "Intermediate", "Advanced"]
                with st.expander(f"{control_code}) {control_name}"):
                    if selected_role == "All":
                        # Display responsible roles for the control
                        responsible_roles = handle_special_control(control_code, threats_data)
                        st.markdown(
                            f"**Responsible role(s):** <span style='color:#f58f2f'> {', '.join(responsible_roles)}</span>",
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
            st.warning("No threats found for the selected role.")
    else:
        st.warning("Please select a role to proceed.")
