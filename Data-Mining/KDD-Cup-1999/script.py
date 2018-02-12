import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

#Loading data
print("Loading Data\n")
df=pd.read_csv('kddcup.data.corrected',header=None)
print("Loading completed \n")

#renaming columns

print("Renaming columns \n")
df.columns = ['duration'
,'protocol_type'
,'service'
,'flag'
,'src_bytes'
,'dst_bytes'
,'land'
,'wrong_fragment'
,'urgent'
,'hot'
, 'num_failed_logins'
,'logged_in'
, 'num_compromised'
, 'root_shell'
, 'su_attempted'
, 'num_root'
, 'num_file_creations'
, 'num_shells'
, 'num_access_files'
,'num_outbound_cmds'
, 'is_host_login'
,'is_guest_login'
,'count'
,'srv_count'
, 'serror_rate'
,'srv_serror_rate'
,'rerror_rate'
, 'srv_rerror_rate'
,'same_srv_rate'
,'diff_srv_rate'
,'srv_diff_host_rate'
,'dst_host_count'
,'dst_host_srv_count'
,'dst_host_same_srv_rate'
,'dst_host_diff_srv_rate'
,'dst_host_same_src_port_rate'
,'dst_host_srv_diff_host_rate'
,'dst_host_serror_rate'
,'dst_host_srv_serror_rate'
,'dst_host_rerror_rate'
,'dst_host_srv_rerror_rate'
,'attackTypes']

print("Shuffling rows to ensure no symmetry or organization of data \n")
df=df.sample(frac=1)

#checking for missing data
missingValues=df.isnull().values.any()
print("Are there any missing values in the data set?",df.isnull().values.any())
print("Hence there is no need to deal with missing data..\n")

#generating some plots

sns.set_style("whitegrid")
fig = plt.figure(figsize=(20, 20))



print("Generating a bar chart for frequency of various attack types present in the data\n")
plot=sns.countplot(y=df['attackTypes'],palette="Greens_d")
plot=plot.get_figure()
plt.show()
plot.savefig("Figures/Figure1.png")


# Compute the correlation matrix and plot heat map
print("Generating a heatmap which represents pair wise correlation between all numeric data types\n")
corr = df.corr()
mask = np.zeros_like(corr, dtype=np.bool)
mask[np.triu_indices_from(mask)] = True
#f, ax = plt.subplots(figsize=(11, 9))
cmap = sns.diverging_palette(220, 10, as_cmap=True)
fig = plt.figure(figsize=(20, 20))
plot=sns.heatmap(corr, mask=mask, cmap=cmap, vmax=.3, center=0, square=True, linewidths=.5, cbar_kws={"shrink": .5})
plot=plot.get_figure()
plt.xticks(rotation=90)
plt.yticks(rotation=0)
plt.show()
plot.savefig("Figures/Figure2.png")

# Using dotplots to understand the distribution of some numeric data
print("Generating a dotplot to understand the range of the duration variable. (This will take some time).\n")
plot=sns.stripplot(x=df['duration'])
plot=plot.get_figure()
plot.savefig("Figures/Figure3.png")
plt.show()

print("Generating dot plot of duration for various attack types. \n")
fig = plt.figure(figsize=(20, 20))
plot=sns.stripplot(x=df['duration'],y=df['attackTypes'])
plot=plot.get_figure()
plot.savefig("Figures/Figure4.png")
plt.show()

print("Generating dot plot of duration for various protocol \n")
fig = plt.figure(figsize=(20, 20))
plot=sns.stripplot(x=df['duration'],y=df['protocol_type'])
plot=plot.get_figure()
plot.savefig("Figures/Figure5.png")
plt.show()

#plotting distribution of count
print("Generating a smooth curve which represents the distribution of the Count variable \n")
fig = plt.figure(figsize=(20, 20))
plot=df['count'].plot(kind="kde")
plot=plot.get_figure()
plot.savefig("Figures/Figure6.png")
plt.show()

#performing binning
print("Based on graph, binning is performed to convert the numeric attribute to a categorical variable\n")
df['count']=pd.cut(df['count'],bins=4,labels=False)


#box plots for dst_host_srv_count
print("Generating distribution of dst_host_srv_count for various attack types")
fig = plt.figure(figsize=(20, 20))
plot=sns.boxplot(x=df['dst_host_srv_count'],y=df['attackTypes'])
plot=plot.get_figure()
plot.savefig("Figures/Figure7.png")
plt.show()

#dot plot for num_failed_logins
print("Generating the distribution of number of failed logins for each attack type. \n")
fig = plt.figure(figsize=(20, 20))
plot=sns.stripplot(x=df['num_failed_logins'],y=df['attackTypes'])
plot=plot.get_figure()
plot.savefig("Figures/Figure8.png")
plt.show()


print("Printing range and other basic statistics of numeric attributes: Deciding on normalization. \n")
print(df.describe())
#Normalization
print("Based on the range, Min-Max normalization is performed on:")
print("Duration")
#print("count")
print("src_bytes")
print("dst_bytes")
print("srv_count")
print("dst_host_srv_count")

print("Performing normalization.")

df['duration']=(df['duration']-df['duration'].min())/(df['duration'].max()-df['duration'].min())
#df['count']=(df['count']-df['count'].min())/(df['count'].max()-df['count'].min())
df['src_bytes']=(df['src_bytes']-df['src_bytes'].min())/(df['src_bytes'].max()-df['src_bytes'].min())
df['dst_bytes']=(df['dst_bytes']-df['dst_bytes'].min())/(df['dst_bytes'].max()-df['dst_bytes'].min())
df['srv_count']=(df['srv_count']-df['srv_count'].min())/(df['srv_count'].max()-df['srv_count'].min())
df['dst_host_srv_count']=(df['dst_host_srv_count']-df['dst_host_srv_count'].min())/(df['dst_host_srv_count'].max()-df['dst_host_srv_count'].min())

print("Normalization complete \n")





