#ui/reset.py
import streamlit as st
import os

def render_global_reset_button():
    st.markdown("### 🗑 Reset Report")

    if st.button("RESET EVERYTHING", key="global_reset_btn"):
        st.session_state["confirm_global_reset"] = True
        st.rerun()

    if st.session_state.get("confirm_global_reset", False):
        st.error("⚠️ CONFIRMĂ ȘTERGEREA TOTALĂ A TUTUROR DATELOR")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("Da – Șterge tot", key="global_reset_yes"):
                if os.path.exists("data/saved_report.json"):
                    try:
                        os.remove("data/saved_report.json")
                    except:
                        pass

                st.session_state.clear()
                st.session_state["confirm_global_reset"] = False
                st.rerun()

        with col2:
            if st.button("Anulează", key="global_reset_no"):
                st.session_state["confirm_global_reset"] = False
                st.rerun()
