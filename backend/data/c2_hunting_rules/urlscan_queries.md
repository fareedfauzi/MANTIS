1- task.tags:”threat”

2- task.tags:”opendir”

3- filename:”.php”

4- task.tags:(@ecarlesi AND threat AND opendir)

5- task.tags:”possiblethreat”

6- task.tags:”c2"

7- task.tags:(c2 AND malware)

8- task.tags:(@ecarlesi) AND page.url:”.php” AND task.tags:threat

9- task.tags:(@ecarlesi) AND page.url:”.php” AND task.tags:possiblethret

Join The Writer's Circle event
10- task.tags:(@ecarlesi) AND page.url:”.php” AND task.tags:malware

11- task.tags:(@ecarlesi) AND page.url:”.php” AND task.tags:c2

12- task.tags:(@ecarlesi) AND page.url:”.php” AND task.tags:phishing

13- task.tags:”c2" AND page.title:”Panel”

14- task.tags:”opendir” AND page.url:”evil.php”

15- task.tags:”opendir” AND page.url.keyword:”con.php”

16- task.tags:”opendir” AND filename:”evil.php”

17- task.tags:”falconsandbox” AND page.url:””

18- task.tags:”falconsandbox” AND page.title:””

19- task.tags:”falconsandbox” AND page.url.keyword:””

20- task.tags:”falconsandbox” AND filename:””

![[Pasted image 20260213200145.png]]
---
