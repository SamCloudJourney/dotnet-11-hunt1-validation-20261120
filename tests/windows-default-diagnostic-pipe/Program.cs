using System;
using System.Threading;

Console.WriteLine($"TARGET_RUNTIME={Environment.Version}");
Console.Out.Flush();
Thread.Sleep(TimeSpan.FromMinutes(5));
