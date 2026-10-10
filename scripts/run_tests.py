import os
from pathlib import Path
import sys
import time
import unittest


TEST_GROUP_NAMES = {
    "test_accept_image": "镜像验收",
    "test_build_pipeline": "镜像构建",
    "test_repository_config": "仓库配置",
    "test_sanitize_vm": "离线净化",
    "test_verify_artifacts": "构建产物校验",
    "test_vm_image": "镜像元数据",
}


class ChineseTestResult(unittest.TestResult):
    def __init__(self, stream):
        super().__init__()
        self.stream = stream
        self.buffer = True
        self.success_count = 0
        self.test_numbers = {}

    def describe_test(self, test):
        parent = getattr(test, "test_case", test)
        test_id = parent.id()
        if test_id not in self.test_numbers:
            self.test_numbers[test_id] = len(self.test_numbers) + 1
        module_name = parent.__class__.__module__.rsplit(".", 1)[-1]
        group_name = TEST_GROUP_NAMES.get(module_name, "测试用例")
        label = f"用例{self.test_numbers[test_id]:03d}：{group_name}"
        if test is parent:
            return f"{label} {test_id}"
        return f"{label} {test._subDescription().strip('()')}"

    def write_status(self, status, test, detail=""):
        suffix = f"，{detail}" if detail else ""
        self.stream.write(f"[{status}] {self.describe_test(test)}{suffix}\n")
        self.stream.flush()

    def _setupStdout(self):
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        super()._setupStdout()

    def startTest(self, test):
        super().startTest(test)
        self.describe_test(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.success_count += 1
        self.write_status("通过", test)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.write_status("失败", test)

    def addError(self, test, err):
        super().addError(test, err)
        self.write_status("错误", test)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.write_status("跳过", test, reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.write_status("预期失败", test)

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._mirrorOutput = True
        self.write_status("意外成功", test)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            status = "失败" if issubclass(err[0], test.failureException) else "错误"
            self.write_status(status, subtest)

    def write_summary(self, elapsed):
        for status, records in (
            ("失败", self.failures),
            ("错误", self.errors),
            ("预期失败", self.expectedFailures),
        ):
            for test, traceback_text in records:
                self.stream.write(f"\n[{status}详情] {self.describe_test(test)}\n")
                self.stream.write(traceback_text)
                if not traceback_text.endswith("\n"):
                    self.stream.write("\n")
        status = "通过" if self.wasSuccessful() else "未通过"
        self.stream.write(
            f"\n[汇总] 测试{status}，运行 {self.testsRun} 项，耗时 {elapsed:.3f} 秒\n"
            f"通过 {self.success_count} 项，失败 {len(self.failures)} 项，"
            f"错误 {len(self.errors)} 项，跳过 {len(self.skipped)} 项，"
            f"预期失败 {len(self.expectedFailures)} 项，"
            f"意外成功 {len(self.unexpectedSuccesses)} 项\n"
        )
        if self.failures or self.errors:
            self.stream.write("[说明] 子测试分别计入失败和错误数量，可能多于测试用例数。\n")
        self.stream.flush()
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            rows = [
                "## 代码测试结果",
                "",
                f"状态：**{status}**，共运行 {self.testsRun} 项，耗时 {elapsed:.3f} 秒。",
                "",
                "| 结果 | 数量 |",
                "|---|---:|",
                f"| 通过 | {self.success_count} |",
                f"| 失败 | {len(self.failures)} |",
                f"| 错误 | {len(self.errors)} |",
                f"| 跳过 | {len(self.skipped)} |",
                f"| 预期失败 | {len(self.expectedFailures)} |",
                f"| 意外成功 | {len(self.unexpectedSuccesses)} |",
                "",
            ]
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(rows) + "\n")


def main():
    project_root = Path(__file__).resolve().parent.parent
    os.chdir(project_root)
    sys.path.insert(0, str(project_root))
    suite = unittest.defaultTestLoader.discover("tests")
    result = ChineseTestResult(sys.stderr)
    started_at = time.perf_counter()
    result.startTestRun()
    try:
        suite.run(result)
    finally:
        result.stopTestRun()
    result.write_summary(time.perf_counter() - started_at)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
