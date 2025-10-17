import simpy
import random
import matplotlib.pyplot as plt


#parametreler değişkendir arrival_rate ve service_rate arası ne kadar kapanırsa paketlerin bekleme süresi artar. 

ARRIVAL_RATE = 1.4   # λ: Ort. geliş hızı (pck/saniye) değişebilir
SERVICE_RATE = 1.5   # μ: Ort. hizmet hızı (pck/saniye) değişebilir
NUM_PACKETS = 10

wait_times = [] 

def packet(env, name, server):
    arrival = env.now
    with server.request() as req:
        yield req  
        wait = env.now - arrival  # Kuyrukta bekleme süresi
        wait_times.append(wait)
        service_time = random.expovariate(SERVICE_RATE)
        yield env.timeout(service_time)  # İşlem süresi


def run_simulation(env, server):
    for i in range(NUM_PACKETS):
        env.process(packet(env, f"pkt-{i}", server))
        interarrival = random.expovariate(ARRIVAL_RATE)
        yield env.timeout(interarrival)


env = simpy.Environment()
server = simpy.Resource(env, capacity=1) #server sayısı 
env.process(run_simulation(env, server))
env.run()


x_values = list(range(1, len(wait_times) + 1))

for value in wait_times:
    print(value)

plt.figure(figsize=(10, 5))
plt.plot(x_values, wait_times, marker='o', linestyle='-', color='darkblue')
plt.title("M/M/1 Kuyrukta Paket Bekleme Süreleri")
plt.xlabel("Paket Numarası")
plt.ylabel("Bekleme Süresi (saniye)")
plt.grid(True)
for x, wait in zip(x_values, wait_times):
    plt.annotate(f"{wait:.2f}", (x, wait), textcoords="offset points", xytext=(0, 8), ha='center')
plt.show()




