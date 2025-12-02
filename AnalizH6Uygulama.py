
from scapy.all import  rdpcap, IP, TCP, UDP
import os
import pandas as pd

from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
import numpy as np

from sklearn.decomposition import PCA
import matplotlib.pyplot as plt


from sklearn.cluster import KMeans


def pcap_analiz(dosya_adi):
    
    if not os.path.exists(dosya_adi):     
        print(f"HATA: '{dosya_adi}' dosyası bulunamadı.")
        return []

    print(f"'{dosya_adi}' dosyası okunuyor...")
    
    # Scapy'nin rdpcap fonksiyonu ile tüm paketleri oku
    paketler = rdpcap(dosya_adi)
    veri_listesi = []

  
    for paket in paketler:
        ozellikler = {
            "Kaynak_IP": "Yok",
            "Hedef_IP": "Yok",
            "Protokol": "Diğer",            # Varsayılan protokol
            "Paket_Uzunlugu": len(paket),   # Paketin toplam bayt cinsinden uzunluğu
            "Kaynak_Port": "Yok",
            "Hedef_Port": "Yok"
        }

        # Paketin IP katmanı içerip içermediğini kontrol et
        if IP in paket:
                                                            # IP katmanı varsa, IP adreslerini çıkar
            ozellikler["Kaynak_IP"] = paket[IP].src
            ozellikler["Hedef_IP"] = paket[IP].dst
            
                                                            # Üst katman protokolünü (TCP/UDP) kontrol et
            if TCP in paket:
                ozellikler["Protokol"] = "TCP"
                ozellikler["Kaynak_Port"] = paket[TCP].sport
                ozellikler["Hedef_Port"] = paket[TCP].dport
            elif UDP in paket:
                ozellikler["Protokol"] = "UDP"
                ozellikler["Kaynak_Port"] = paket[UDP].sport
                ozellikler["Hedef_Port"] = paket[UDP].dport
            # ICMP veya diğer IP tabanlı protokoller burada eklenebilir
            elif paket[IP].proto == 1: # 1: ICMP protokol numarası
                ozellikler["Protokol"] = "ICMP"
        
        # Eğer IP katmanı yoksa (örneğin sadece ARP veya Ethernet paketiyse)
        else:
            # Protokolü Ethernet frame tipine göre belirle
            if paket.type == 2054: # 2054: ARP protokol tipi
                ozellikler["Protokol"] = "ARP"
            
        veri_listesi.append(ozellikler)

    return veri_listesi


def akis_bazli_ozellikler(df, zaman_kolonu=None):
    
    #Paket DataFrame'ini alır, akışlara göre gruplar ve özet istatistikler  çıkarır.
    

    # Akışı tanımlayan temel 5'li demet
    grup_kolonlari = ["Kaynak_IP", "Hedef_IP", "Protokol", "Kaynak_Port", "Hedef_Port"]
    
    
    # Akışa göre gruplama ve özet istatistikleri hesaplama
    
    akis_df = df.groupby(grup_kolonlari).agg(
        # Akış özellikleri
        Akis_Paket_Sayisi=('Protokol', 'size'), 
        Ort_Paket_Uzunlugu=('Paket_Uzunlugu', 'mean'),
        Min_Paket_Uzunlugu=('Paket_Uzunlugu', 'min'),
        Max_Paket_Uzunlugu=('Paket_Uzunlugu', 'max'),
        Tekil_Protokol_Sayisi=('Protokol', 'nunique')
    ).reset_index()


    print("Akış Bazlı Özellik Çıkarma Tamamlandı.")
    return akis_df


#------------  Makina Öğrenmesi fonksiyonları  ------------------

def ml_icin_veri_hazirla(df_akis):
    """
    Akış DataFrame'ini alır, kategorik verileri kodlar ve sayısal verileri ölçekler.
    """
    print("\n--- Makine Öğrenimi İçin Veri Ön İşleme Başlatılıyor ---")
    
    # ADIM 1: Veri Tipi Standardizasyonu (Önceki hatanın çözümü)
    df_akis['Protokol'] = df_akis['Protokol'].astype(str)
    df_akis['Kaynak_Port'] = df_akis['Kaynak_Port'].astype(str)   #port numarası sayısal değildir burada, kategorik olduğu için metin olarak alacağız. 
    df_akis['Hedef_Port'] = df_akis['Hedef_Port'].astype(str)
    
    # 1. Özellik Türlerini Tanımlama
    kategorik_ozellikler = ["Protokol", "Kaynak_Port", "Hedef_Port"]
    sayisal_ozellikler = [
        "Akis_Paket_Sayisi", 
        "Ort_Paket_Uzunlugu", 
        "Min_Paket_Uzunlugu", 
        "Max_Paket_Uzunlugu",
        "Tekil_Protokol_Sayisi"
    ]
    
    # 2. Dönüştürücü (Transformer) Tanımlama
    on_isleme = ColumnTransformer(
        transformers=[
            ('sayisal', StandardScaler(), sayisal_ozellikler),
            ('kategorik', OneHotEncoder(handle_unknown='ignore'), kategorik_ozellikler)
        ],

        remainder='drop' 
    )


    X_ham = df_akis[sayisal_ozellikler + kategorik_ozellikler]

    # fit_transform ile dönüşümü uygula
    X_islenmis_np = on_isleme.fit_transform(X_ham)

    print("Veri Ön İşleme Tamamlandı.")
    print(f"Oluşturulan Özellik Matrisinin Boyutu (Satır, Sütun): {X_islenmis_np.shape}")
    
    return X_islenmis_np

def kmeans_kumeleme(X_islenmis_np, kume_sayisi=3):
    
    print(f"\n--- K-Means Kümeleme Yapılıyor --- (K={kume_sayisi}) ---")
    

    kmeans = KMeans(n_clusters=kume_sayisi, random_state=42, n_init='auto')
    kmeans.fit(X_islenmis_np)
    
    kume_etiketleri = kmeans.labels_
     
    print("Kümeleme Tamamlandı.")
    return kume_etiketleri

def sonuclar_kayit(df_akis, kume_etiketleri, dosya_yolu):
    
    df_akis['Akis_Kumesi'] = kume_etiketleri
    
    print("\n--- Kümeleme Sonuçları ---")
    
    print(df_akis['Akis_Kumesi'].value_counts())
    
  
    df_akis.to_csv(dosya_yolu, index=False)
    print(f"\n Kümelemeden sonra sonuçlar '{os.path.basename(dosya_yolu)}' dosyasına kaydedildi.")
    
    kume_ozeti = df_akis.groupby('Akis_Kumesi')[['Akis_Paket_Sayisi', 'Ort_Paket_Uzunlugu']].mean()
    print("\nKüme Ortalamaları (Özet):")
    print(kume_ozeti)
    
    #Görseller-------------------------------------------------------------
    
def gorsel_sonuclar(X_islenmis_np, kume_etiketleri, kume_sayisi):
    

    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_islenmis_np)
    

    df_gorsel = pd.DataFrame(data = X_pca, columns = ['Bilesen_1', 'Bilesen_2'])
    df_gorsel['Kume'] = kume_etiketleri
    
   
    aciklanan_varyans = np.sum(pca.explained_variance_ratio_)
    print(f"İlk 2 Ana Bileşen Toplam Varyansın: %{aciklanan_varyans * 100:.2f}'ini Açıklıyor.")


    
    print("Görselleştirme verisi hazırlandı.")
    
    return df_gorsel

    
    
#------------  Ana Program  ------------------
if __name__ == "__main__":
    

    DosyaAdi="/Users/honour/Documents/GitHub/NetAnalysisC25/analiz.pcap"     #birinci analiz dosyası
    #DosyaAdi="/Users/honour/Documents/GitHub/NetAnalysisC25/chargen-tcp.pcap" #ikinci analiz dosyası
    Program_Yolu ="/Users/honour/Documents/GitHub/NetAnalysisC25/"
    KUME_SAYISI = 3  #analiz pcap dosyası için 3
    # ...
    
    # 1. temel paket özelliklerini çıkarma
    paket_verileri = pcap_analiz(DosyaAdi) 
    
    if paket_verileri:
        # df_paket ve df_akis oluşturma adımları
        df_paket = pd.DataFrame(paket_verileri)
        df_paket.to_csv(Program_Yolu + "paket_ozellikleri.csv", index=False)
        
        df_akis = akis_bazli_ozellikler(df_paket)
        df_akis.to_csv(Program_Yolu + "akis_ozellikleri.csv", index=False)
                
        # 2. ML veri önişleme
        X_ml_hazir = ml_icin_veri_hazirla(df_akis)
        
        # 3. K-Means Kümeleme Uygulama
        kume_etiketleri = kmeans_kumeleme(X_ml_hazir, kume_sayisi=KUME_SAYISI)
        
        # 4. Sonuçları Kaydetme
        final_csv_yolu = Program_Yolu + "akis_sonuclari_kumelenmis.csv"
        sonuclar_kayit(df_akis.copy(), kume_etiketleri, final_csv_yolu)
        
        
        # 5. Görselleştirme verisini hazırla (PCA indirgeme)
        df_gorsel = gorsel_sonuclar(X_ml_hazir, kume_etiketleri, KUME_SAYISI)
        
        plt.figure(figsize=(10, 7))
        scatter = plt.scatter(
            df_gorsel['Bilesen_1'], 
            df_gorsel['Bilesen_2'], 
            c=df_gorsel['Kume'],
            cmap='viridis', 
            s=50, 
            alpha=0.6
        )
        
        plt.xlabel('Ana Bileşen 1 (PCA)')
        plt.ylabel('Ana Bileşen 2 (PCA)')
        plt.title(f'Ağ Akışlarının K-Means Kümeleme Sonucu (K={KUME_SAYISI}, PCA ile azaltılmış)')
        
        # Legend ekleme
        legend1 = plt.legend(*scatter.legend_elements(), title="Küme Etiketleri")
        plt.gca().add_artist(legend1)
        
        # Grafiği belirtilen klasöre kaydet
        kayit_dosya_adi = "analiz_sonuc.png"
        plt.savefig(Program_Yolu + kayit_dosya_adi)
        
        print(f"\n Görsel: '{kayit_dosya_adi}' dosyası şuraya kaydedildi: {Program_Yolu}")
        
    else:
        print("\nHata oluştu.")


#zaman analizi eksik eklenebilir. 
# Paketlerin geliş zaman aralıkları (arrival time) veya saniyedeki paket sayısı (pps) gibi zaman bazlı özellikler DDoS tespitinde daha kritiktir verilerdir. 

print( "devam ediyor...")

