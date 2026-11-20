using System;
using System.IO;
using System.Linq;

string root = Path.Combine(Path.GetTempPath(), "dotnet11-benign-path-check-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    foreach (string component in new[] { "ordinary", "child.", "child " })
    {
        string proposed = Path.GetFullPath(Path.Combine(root, component, "marker.txt"));
        Directory.CreateDirectory(Path.GetDirectoryName(proposed)!);
        File.WriteAllText(proposed, "inert");
        string materialized = Directory.GetFiles(root, "marker.txt", SearchOption.AllDirectories).Single();
        string observedComponent = Path.GetFileName(Path.GetDirectoryName(materialized)!);
        Console.WriteLine($"{component.TrimEnd('.', ' ')}: canonicalMatchesMaterialized={string.Equals(proposed, materialized, StringComparison.Ordinal)}; observedChildMatchesInput={string.Equals(component, observedComponent, StringComparison.Ordinal)}");
        File.Delete(materialized);
        Directory.Delete(Path.GetDirectoryName(materialized)!);
    }
}
finally
{
    Directory.Delete(root, recursive: true);
}
