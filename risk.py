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

# Step 3: Perform Risk Assessment
def perform_risk_assessment(selected_threats, user_responses, threats_data, controls_dread):
    results = {
        'Threat': [],
        'Impact Residue': [],
        'Likelihood Residue': [],
        'Qualitative Risk': []
    }

    # Group the controls by threat and calculate Impact and Likelihood
    for threat_code, threat_name in selected_threats:
        # st.subheader(f"Debug: {threat_name} ({threat_code})")
        threat_controls = [ctrl for ctrl in threats_data['Threats'] if ctrl['Code'] == threat_code][0]['Controls']

        # Prepare the group data with necessary information for calculations
        group_data = []
        for control in threat_controls:
            control_code = control['Code']
            weight = control['Normalized Weights']
            mitigation_level = user_responses[control_code]

            # Get control details from controls_dread.json
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

        # Calculate maximum possible sums for the factors
        max_sums = calculate_max_sums(group_data, ['D', 'R', 'E', 'A', 'D1'])
        max_sum_d = max_sums['D']
        max_sum_r = max_sums['R']
        max_sum_e = max_sums['E']
        max_sum_a = max_sums['A']
        max_sum_d1 = max_sums['D1']

        max_sum_impact_mitigation = max_sum_d + max_sum_a
        max_sum_likelihood_mitigation = max_sum_r + max_sum_e + max_sum_d1

        # Calculate mitigation sums based on user inputs
        mitigation_sums = calculate_mitigation_sums(group_data, ['D', 'R', 'E', 'A', 'D1'])
        mitigation_sum_d = mitigation_sums['D']
        mitigation_sum_r = mitigation_sums['R']
        mitigation_sum_e = mitigation_sums['E']
        mitigation_sum_a = mitigation_sums['A']
        mitigation_sum_d1 = mitigation_sums['D1']

        obtained_sum_impact = mitigation_sum_d + mitigation_sum_a
        obtained_sum_likelihood = mitigation_sum_r + mitigation_sum_e + mitigation_sum_d1

        # Debug output for max sums and mitigation sums
        # st.text(f"Max Sums: D={max_sum_d}, R={max_sum_r}, E={max_sum_e}, A={max_sum_a}, D1={max_sum_d1}")
        # st.text(f"Mitigation Sums: D={mitigation_sum_d}, R={mitigation_sum_r}, E={mitigation_sum_e}, A={mitigation_sum_a}, D1={mitigation_sum_d1}")
        # st.text(f"Obtained Sum Impact={obtained_sum_impact}, Obtained Sum Likelihood={obtained_sum_likelihood}")
        # st.text(f"Max Sum Impact Mitigation={max_sum_impact_mitigation}, Max Sum Likelihood Mitigation={max_sum_likelihood_mitigation}")

        # Calculate Impact Residue and Likelihood Residue
        impact_residue = round((max_sum_impact_mitigation - obtained_sum_impact) / max_sum_impact_mitigation, 2) if max_sum_impact_mitigation != 0 else 0
        likelihood_residue = round((max_sum_likelihood_mitigation - obtained_sum_likelihood) / max_sum_likelihood_mitigation, 2) if max_sum_likelihood_mitigation != 0 else 0

        # Debug output for impact and likelihood residues
        # st.text(f"Impact Residue: {impact_residue}")
        # st.text(f"Likelihood Residue: {likelihood_residue}")

        # Map Impact and Likelihood to Qualitative Levels
        impact_level = map_to_qualitative(impact_residue)
        likelihood_level = map_to_qualitative(likelihood_residue)

        # Determine Qualitative Risk
        if impact_residue == 0 and likelihood_residue == 0:
            qualitative_risk = "No Risk"
        else:
            qualitative_risk = qualitative_risk_matrix.get((impact_level, likelihood_level))

        # Debug output for risk
        # st.text(f"Qualitative Risk: {qualitative_risk}\n")

        # Store the results
        results['Threat'].append(threat_name)
        results['Impact Residue'].append(impact_residue)
        results['Likelihood Residue'].append(likelihood_residue)
        results['Qualitative Risk'].append(qualitative_risk)

    # Convert results to DataFrame for better readability
    results_df = pd.DataFrame(results)

    # Apply color coding to qualitative risk levels
    def color_code_risk(val):
        color_map = {
        "Very Low": "background-color: #008000; color: #FFFFFF;",  # Green background, White text
        "Low": "background-color: #FFFF00; color: #000000;",       # Yellow background, Black text
        "Medium": "background-color: #A5762A; color: #FFFFFF;",    # Brown background, White text
        "High": "background-color: #ED7777; color: #FFFFFF;",      # Light Coral background, White text
        "Critical": "background-color: #ED0E0E; color: #FFFFFF;"   # Red background, White text
    }
        return color_map.get(val, "")

    styled_df = results_df.style.applymap(color_code_risk, subset=["Qualitative Risk"])

    return styled_df

# Streamlit application
st.title("Control-based Risk Assessment")

# Step 1: Select applicable threats
st.header("Step 1: Select Applicable Threats")
threats_options = [(threat['Code'], threat['Name']) for threat in threats_data['Threats']]
all_threats_option = ("ALL", "Select All Threats")
threats_options.insert(0, all_threats_option)

selected_threats = st.multiselect(
    "Select the threats that are applicable in your scenario:",
    threats_options,
    format_func=lambda x: x[1]
)

# Handle the case where 'Select All Threats' is chosen
if any(threat[0] == "ALL" for threat in selected_threats):
    selected_threats = threats_options[1:]

# Check if any threats are selected
if selected_threats:
    # Step 2: Generate form for selected controls
    st.header("Step 2: Control Mitigation Level Selection")

    selected_controls = set()
    for threat_code, threat_name in selected_threats:
        for threat in threats_data['Threats']:
            if threat['Code'] == threat_code:
                for control in threat['Controls']:
                    selected_controls.add(control['Code'])

    user_responses = {}

    # Generate an expanded box for each selected control
    for control_code in selected_controls:
        control_name = next((ctrl['Name'] for ctrl in controls_dread['Controls'] if ctrl['Code'] == control_code), "Unknown Control")
        mitigation_levels = ["N/A", "Basic", "Intermediate", "Advanced"]
        
        with st.expander(f"{control_code}) {control_name}"):
            selected_level = st.radio(
                f"What is the level of implementation of the control in your scenario?",
                mitigation_levels,
                key=control_code
            )

            # Get the description for the selected level
            if selected_level != "N/A":
                level_description = controls_data['Controls'].get(control_code, {}).get('Mitigation Level', {}).get(selected_level, "Description not available.")
                st.write(f"**Selected mitigation level:** {level_description}")
            
            # Save user response
            user_responses[control_code] = MITIGATION_LEVELS_MAPPING[selected_level]

    # Step 3: Perform Risk Assessment
    if st.button("Risk Assessment"):
        st.header("Step 3: Risk Assessment Result")

        # Perform risk assessment
        styled_df = perform_risk_assessment(selected_threats, user_responses, threats_data, controls_dread)

        # Display the results with color coding
        st.write("Risk Assessment Results")
        st.dataframe(styled_df)
else:
    st.warning("Please select at least one threat to proceed.")
