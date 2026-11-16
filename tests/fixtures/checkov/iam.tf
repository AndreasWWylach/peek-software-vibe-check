resource "aws_iam_policy" "wild" {
  name        = "wildcard-policy"
  description = "flags IAM wildcards"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
