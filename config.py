import os
import streamlit as st
def config():
# ##---------Config--------------------------
    base_path = os.getcwd()
    icon_path = os.path.join(base_path, "icon.png")
    st.set_page_config(page_title="DIWAR", layout="wide", initial_sidebar_state="expanded", page_icon=icon_path)
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
    logo_path = os.path.join(base_path, "d.png")
    headers = [
        ("About", "#f3b61f"),
        ("How It Works", "#f3b61f")
    ]
    configure_sidebar(headers)

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