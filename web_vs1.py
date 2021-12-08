import streamlit as st
import pandas as pd
import plotly.express as px
from geopy.geocoders import Nominatim
import urllib.request
import os.path, time
from bs4 import BeautifulSoup
import folium
import plotly.graph_objects as go
from PIL import Image
from IPython.display import HTML
import runpy

st.set_page_config(
    page_title="APIP",
    page_icon="chart_with_upwards_trend",
    layout="wide",
)

page = st.sidebar.selectbox("Choose your page", ["IPDB Reports", "Virus Total and IP Quality Score","OTX Pulses and PulseDive" ,  "API Configuration"])
page2 = st.sidebar.text_input("Enter IP to be investigated")
if st.sidebar.button("Investigate"):
    with st.spinner('Requesting all APIs and Parsing it - It may take a while'):
        time.sleep(5)

        tex1 = open("ipi.txt", "w")
        tex1.write(page2)
        tex1.close()
        runpy.run_path(path_name='main.py')
        st.success('Done!')



if page == "IPDB Reports":



    st.title('Exploring IPDB Reports ')
    image = Image.open('abuseipdb.png.png')
    st.image(image)

    df1 = pd.read_csv("ip_rep.csv")



    st.subheader("Analyzing general data by country and date")
    st.markdown("Displayed by much of times as ID as Y axis")

    fig1 = px.scatter(df1, x="Date reported", y="User ID", color="Country Name")
    st.write(fig1)




    df_count = pd.DataFrame(df1, columns=['Country Name'])

    df_cnt_u = df_count['Country Name'].unique()

    country = st.selectbox("Select the country:", df_cnt_u)

    fig = px.line(df1[df1['Country Name'] == country],
                      x="Date reported", y="User ID", title=country)
    st.plotly_chart(fig)





    st.subheader("General data and bar chart of reports ")



    st.markdown('Reports by any type or combination ')
    st.bar_chart(df1['Categories'])



    df1 = pd.read_csv("ip_rep.csv")

    st.markdown('All IPDB reports displayed by date  ')
    st.dataframe(df1)
    st.subheader("Number of reports by country and  data about the reported IP ")








    df_count = pd.DataFrame(df1, columns=['Country Name'])

    df_cnt = df_count['Country Name'].value_counts()
    st.write(df_cnt)
    st.subheader("Main data of the IP")



    df = pd.read_csv("ip_main.csv")

    st.write(df)



if page == "Virus Total and IP Quality Score":

    st.subheader("General data and bar chart of reports ")

    image2 = Image.open('IPQ.png')

    df2 = pd.read_csv("vpn_check.csv")

    image3 = Image.open('VirusTotal-logo.png')

    st.subheader("Virus Total Response ")



    st.image(image3)
    pd7 = pd.read_csv("vt_i.csv" )

    st.dataframe(pd7, 1200, 1200)




    st.subheader("IPQuality response")

    st.image(image2)
    st.dataframe(df2, width=1200 , height=700)





if page == "OTX Pulses and PulseDive":


    st.subheader("PulseDive Response")
    image5 = Image.open('pulsedive.png')
    st.image(image5 ,200 , 200)
    pd11 = pd.read_csv("pulsedv.csv")

    st.write(pd11)

    st.subheader("OTX Pulses")
    image6 = Image.open('otx.png')
    st.image(image6 ,200 ,200)
    pd5 = pd.read_json("otxone.json")

    st.write(pd5)








if page == "API Configuration":
    pss_vt = st.text_input("Enter API KEY Virustotal ")
    st.title(pss_vt)

    pss_ipdb = st.text_input("Enter API KEY IPDB ")
    st.title(pss_ipdb)

    pss_OTX = st.text_input("Enter API KEY OTX")
    st.title(pss_OTX)

    pss_ipq = st.text_input("Enter API KEY IPQualityScore")
    st.title(pss_ipq)

    pss_pul = st.text_input("Enter API KEY Pulse Dive")
    st.title(pss_pul)

    if st.button('Save Keys'):
        text_file = open("keys.txt", "w")
        text_file.write(pss_vt)
        text_file.write("\n")
        text_file.write(pss_ipdb)
        text_file.write("\n")

        text_file.write(pss_OTX)
        text_file.write("\n")

        text_file.write(pss_ipq)
        text_file.write("\n")

        text_file.write(pss_pul)
        text_file.write("\n")

        text_file.close()

    else :
        pass




