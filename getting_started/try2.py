dicto={"bold guy":"al", "middle guy":"john", "short guy":"jack"}
#print dicto
#print dicto["al"]
#print dicto[2345]

dicto2=dict(mele=12,pere=33,banane=11)

#print dicto2["mele"]
#print dicto2["banane"]

print ("La leggenda di {0[bold guy]}, {0[middle guy]} e {0[short guy]}".format(dicto))
