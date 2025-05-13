from qunetsim.components import Host, Network
from qunetsim.objects import Logger, Qubit
import asyncio

Logger.DISABLED = True

# Define Alice's behaviour
def alice_behaviour(host, receiver):
  for i in range(5):
    q = Qubit(host)
    q.H()
    print(f"{host.host_id} Sending qubit %d." % (i+1))
    host.send_qubit(receiver, q, await_ack = True)
    print(f"{host.host_id} Qubit %d was received by %s." % (i+1, receiver))



# Define Bob's behaviour
def bob_behaviour(host, sender):
  for _ in range(5):
    q = host.get_data_qubit(sender, wait = 10)
    # if q:
    print(f"{host.host_id} Received a qubit in the {q.measure()} state")
    # else:
    #   print(f"{host.host_id} No qubit received")

# Initialize network and run simulation
def run():
  network = Network.get_instance()
  nodes = ["Alice", "Bob", "Curt", "Dan"]
  network.start()

  alice = Host("Alice")
  alice.add_connection("Bob")
  alice.add_connection("Curt")
  alice.add_connection("Dan")
  alice.start()

  bob = Host("Bob")
  bob.add_connection("Alice")
  bob.add_connection("Curt")
  bob.add_connection("Dan")
  bob.start()

  curt = Host("Curt")
  curt.add_connection("Alice")
  curt.add_connection("Bob")
  curt.add_connection("Dan")
  curt.start()

  dan = Host("Dan")
  dan.add_connection("Alice")
  dan.add_connection("Bob")
  dan.add_connection("Curt")
  dan.start()

  # bob.get_data_qubit()

  network.add_host(alice)
  network.add_host(bob)
  network.add_host(curt)
  network.add_host(dan)

  # Schedule their behaviours
  alice.run_protocol(alice_behaviour, (bob.host_id,))
  bob.run_protocol(bob_behaviour, (alice.host_id,))

  # Allow time for protocola to run
  # network.run(duration=10)
  network.stop(True)

# run()
if __name__ == "__main__":
  # asyncio.get_event_loop().run_until_complete(asyncio.ensure_future(run()))
  run()